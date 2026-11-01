"""
qvault.budgets
==============

Resource isolation for the components that parse hostile input.

Why a budget is a security control here
---------------------------------------
Upstream's own documentation records the motivating incident: a 399-byte backup file
holding 291,000 message rows produced gigabytes of findings and stalled the scanner.
The artifact was tiny; the *expansion* was chosen by whoever wrote the file. Any parser
reading attacker-authored input has an expansion ratio the attacker controls, so
"how much CPU may this take" is not a performance question, it is the difference
between a triage run and a denial of service.

So each isolated component gets a hard budget, and exceeding it is a *finding about
the evidence*, not merely an error: a read that was killed for blowing its budget has
a coverage gap, and anything resting on it is lower grade (rule F3).

Two rules that make this honest
-------------------------------
**A budget kill is not a clean result.** `gaps_for()` turns every exceeded dimension
into a telemetry gap, so a truncated parse cannot be reported as a completed one.

**Output is capped as well as input.** An expansion attack is defeated by bounding what
a parser may *emit*, not only what it may read.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import findings as F
from . import isolation as I

# Budgets per isolated component (see qvault/isolation.py for the zone model).
# Numbers are deliberately conservative starting points, not measurements: the point
# is that a ceiling exists and is enforced, and tuning is a calibration task.
BUDGETS: dict[str, dict] = {
    I.EVIDENCE_READER: {
        "wall_s": 300.0, "memory_mb": 1024.0, "output_bytes": 64 * 1024 * 1024,
        "open_files": 256, "artifact_bytes": 512 * 1024 * 1024,
    },
    I.DB_PARSER: {
        "wall_s": 180.0, "memory_mb": 512.0, "output_bytes": 32 * 1024 * 1024,
        "open_files": 128, "artifact_bytes": 8 * 1024 * 1024 * 1024,
    },
    I.INDICATOR_PROCESSING: {
        "wall_s": 60.0, "memory_mb": 256.0, "output_bytes": 16 * 1024 * 1024,
        "open_files": 32, "artifact_bytes": 64 * 1024 * 1024,
    },
    I.REPORT_GENERATION: {
        "wall_s": 120.0, "memory_mb": 512.0, "output_bytes": 128 * 1024 * 1024,
        "open_files": 64, "artifact_bytes": 0,
    },
    I.AI_ANALYSIS: {
        "wall_s": 90.0, "memory_mb": 512.0, "output_bytes": 4 * 1024 * 1024,
        "open_files": 16, "artifact_bytes": 0,
    },
}

DIMENSIONS = ("wall_s", "memory_mb", "output_bytes", "open_files", "artifact_bytes")

#: Expansion ratio above which an input is worth reporting as suspicious in itself,
#: independent of what the parser found inside it.
EXPANSION_ALERT_RATIO = 1000.0


class BudgetExceeded(RuntimeError):
    """Raised when a component must be stopped for exceeding its budget."""


@dataclass(frozen=True)
class Usage:
    wall_s: float = 0.0
    memory_mb: float = 0.0
    output_bytes: int = 0
    open_files: int = 0
    artifact_bytes: int = 0

    def as_dict(self) -> dict:
        return {d: getattr(self, d) for d in DIMENSIONS}


def check(component: str, usage: Usage) -> dict:
    """Compare usage against the component's budget."""
    if component not in BUDGETS:
        raise KeyError(f"no budget defined for {component!r}; known: {sorted(BUDGETS)}")
    budget = BUDGETS[component]
    exceeded = [
        d for d in DIMENSIONS
        if getattr(usage, d) > budget[d] and not (d == "artifact_bytes" and budget[d] == 0)
    ]
    # artifact_bytes == 0 means the component may not read artifacts at all
    if budget["artifact_bytes"] == 0 and usage.artifact_bytes > 0:
        exceeded.append("artifact_bytes_forbidden")

    ratio = (
        usage.output_bytes / usage.artifact_bytes
        if usage.artifact_bytes else 0.0
    )
    return {
        "component": component,
        "usage": usage.as_dict(),
        "budget": dict(budget),
        "exceeded": sorted(set(exceeded)),
        "within_budget": not exceeded,
        "expansion_ratio": round(ratio, 2),
        "expansion_alert": ratio >= EXPANSION_ALERT_RATIO,
        "action": (
            "kill the component, preserve its partial output as evidence, and record the "
            "gap; do not re-run unbounded against the same input"
            if exceeded else "continue"
        ),
    }


def assert_within(component: str, usage: Usage) -> dict:
    result = check(component, usage)
    if not result["within_budget"]:
        raise BudgetExceeded(
            f"{component} exceeded {', '.join(result['exceeded'])}: "
            f"{result['action']}"
        )
    return result


def gaps_for(component: str, usage: Usage) -> tuple[str, ...]:
    """Telemetry gaps implied by a budget that stopped collection.

    A killed parse did not observe what it was going to observe, so findings resting
    on it are lower grade. This is rule F3 applied to resource exhaustion.
    """
    result = check(component, usage)
    gaps = [f"budget_exceeded:{d}" for d in result["exceeded"]]
    if result["expansion_alert"]:
        gaps.append(
            f"expansion_ratio:{result['expansion_ratio']:.0f}:1: the input's size does not "
            "account for its output, which is attacker-chosen"
        )
    return tuple(gaps)


def observation(component: str, usage: Usage, statement: str) -> F.Observation:
    """A parser result, graded down by whatever its budget cost it."""
    gaps = gaps_for(component, usage)
    return F.Observation(
        statement=statement,
        plane="historical_record",
        grade=F.INFERRED if not gaps else F.HYPOTHESIS,
        telemetry_gaps=gaps,
        source=f"{component}:budgeted",
    )


def audit_budgets() -> list[dict]:
    """Every isolated component must have a ceiling, including for output."""
    missing = [c for c in I.COMPONENTS if c not in BUDGETS]
    violations = [
        {"rule": "no_budget", "component": c,
         "why": "component parses hostile input with no resource ceiling"}
        for c in missing
    ]
    for component, budget in BUDGETS.items():
        for dim in DIMENSIONS:
            if dim not in budget:
                violations.append({"rule": "incomplete_budget", "component": component,
                                   "why": f"no ceiling for {dim}"})
    return violations

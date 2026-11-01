"""
qvault.isolation
================

Zone placement for the five components that touch attacker-controlled data.

The components to isolate
-------------------------
* **evidence readers** — parse firmware images, PE/FFS modules
* **database parsers** — parse hives, SQLite, registry, index databases
* **indicator processing** — ingest threat intelligence
* **report generation** — emit findings as documents
* **AI-assisted analysis** — anything model-mediated

Why these five and not the vault
--------------------------------
The vault holds ciphertext, which is inert. These five *interpret* bytes written by
aggressors, so each is a code-execution surface whose input is chosen by the enemy.
Isolating them from the vault is the easy half. The hard half is isolating them from
each other, because the dangerous paths are pairwise:

* a reader compromised by a crafted FFS volume that can reach the report generator
  can rewrite conclusions;
* indicator processing that can write findings can *suppress* them, which is the
  quiet version of the attack (A4 in report/ARCHITECTURAL_LIMITATIONS.md);
* AI analysis that can read decrypted artifacts is an exfiltration channel with a
  prompt-injection front door.

So placement is not a label. `place()` refuses a component in a zone that cannot
meet it, `assert_separated()` refuses pairings that defeat the model, and
`may_flow()` refuses data paths that carry plaintext somewhere it does not belong.

The AI-specific rule
--------------------
Model output enters the evidence chain as an `Observation` graded no higher than
HYPOTHESIS, never as a `Finding`. A model that has read attacker-influenced text is
an unreliable narrator about that text, and prompt injection makes its conclusions
an input to the adversary's design. Grading discipline is in `ai_observation()`.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import findings as F

# --- zones ---------------------------------------------------------------

INGEST = "ingest"
VAULT = "vault"
KEYSTORE = "keystore"
ENCLAVE = "enclave"
INTEL = "intel"
PRESENTATION = "presentation"
AI = "ai"

ZONES = (INGEST, VAULT, KEYSTORE, ENCLAVE, INTEL, PRESENTATION, AI)

# Capabilities a zone confers. Isolation is expressed as the absence of these.
ZONE_CAPS: dict[str, frozenset[str]] = {
    INGEST: frozenset({"artifact_intake", "vault_write_append", "network_inbound"}),
    VAULT: frozenset({"blob_store", "envelope_read", "finding_read"}),
    KEYSTORE: frozenset({"key_access"}),
    ENCLAVE: frozenset({"artifact_read", "artifact_decrypt", "finding_write",
                        "telemetry_read"}),
    INTEL: frozenset({"intel_read", "intel_label"}),
    PRESENTATION: frozenset({"finding_read", "report_emit"}),
    AI: frozenset({"model_call", "finding_read", "envelope_read"}),
}

# --- components ----------------------------------------------------------

EVIDENCE_READER = "evidence_reader"
DB_PARSER = "db_parser"
INDICATOR_PROCESSING = "indicator_processing"
REPORT_GENERATION = "report_generation"
AI_ANALYSIS = "ai_analysis"

COMPONENTS = (EVIDENCE_READER, DB_PARSER, INDICATOR_PROCESSING, REPORT_GENERATION, AI_ANALYSIS)


class IsolationError(ValueError):
    """Raised when a component's placement would break a stated guarantee."""


@dataclass(frozen=True)
class Requirement:
    component: str
    must_have: frozenset[str]
    must_not_have: frozenset[str]
    rationale: str


REQUIREMENTS: dict[str, Requirement] = {
    EVIDENCE_READER: Requirement(
        EVIDENCE_READER,
        must_have=frozenset({"artifact_read"}),
        must_not_have=frozenset({
            "network_inbound", "network_egress", "model_call", "key_access",
            "vault_write_append", "whitelist_write", "report_emit",
        }),
        rationale="parses bytes chosen by the adversary, so it must not be able to "
                  "reach a network, a key, or a conclusion",
    ),
    DB_PARSER: Requirement(
        DB_PARSER,
        must_have=frozenset({"artifact_read"}),
        must_not_have=frozenset({
            "network_inbound", "network_egress", "model_call", "key_access",
            "vault_write_append", "whitelist_write", "report_emit",
        }),
        rationale="hives and database files are a well-trodden parser exploitation "
                  "surface and deserve the same confinement as firmware readers",
    ),
    INDICATOR_PROCESSING: Requirement(
        INDICATOR_PROCESSING,
        must_have=frozenset({"intel_read"}),
        must_not_have=frozenset({
            "artifact_read", "artifact_decrypt", "finding_write", "whitelist_write",
            "key_access", "model_call", "report_emit", "network_inbound",
        }),
        rationale="must not be able to author or suppress findings: an indicator "
                  "pipeline with write access to detection state is a suppression "
                  "primitive, not an enrichment one",
    ),
    REPORT_GENERATION: Requirement(
        REPORT_GENERATION,
        must_have=frozenset({"report_emit"}),
        must_not_have=frozenset({
            "artifact_read", "artifact_decrypt", "key_access", "model_call",
            "network_inbound", "network_egress", "whitelist_write",
        }),
        rationale="consumes graded findings and envelopes only, never raw bytes: a "
                  "report generator that reads artifacts can be injected by them, and "
                  "one that reads plaintext is an exfiltration route",
    ),
    AI_ANALYSIS: Requirement(
        AI_ANALYSIS,
        must_have=frozenset({"model_call"}),
        must_not_have=frozenset({
            "artifact_read", "artifact_decrypt", "key_access", "vault_write_append",
            "finding_write", "whitelist_write", "network_inbound",
        }),
        rationale="model-mediated analysis of attacker-influenced text is prompt "
                  "injectable, so it may read graded findings but not plaintext "
                  "artifacts, and it may not write findings at all",
    ),
}

# Pairs that must never share a zone, even if the capability table would allow it.
SEPARATION_REQUIRED = (
    (AI_ANALYSIS, EVIDENCE_READER),
    (AI_ANALYSIS, DB_PARSER),
    (AI_ANALYSIS, INDICATOR_PROCESSING),
    (REPORT_GENERATION, EVIDENCE_READER),
    (REPORT_GENERATION, DB_PARSER),
    (INDICATOR_PROCESSING, REPORT_GENERATION),
)

# Default placement: one component per zone, no sharing.
DEFAULT_PLACEMENT = {
    EVIDENCE_READER: ENCLAVE,
    DB_PARSER: ENCLAVE,
    INDICATOR_PROCESSING: INTEL,
    REPORT_GENERATION: PRESENTATION,
    AI_ANALYSIS: AI,
}


def place(component: str, zone: str) -> dict:
    """Validate one placement, returning what it guarantees and what it costs."""
    if component not in REQUIREMENTS:
        raise IsolationError(f"unknown component {component!r}; known: {COMPONENTS}")
    if zone not in ZONE_CAPS:
        raise IsolationError(f"unknown zone {zone!r}; known: {ZONES}")

    req = REQUIREMENTS[component]
    caps = ZONE_CAPS[zone]

    missing = req.must_have - caps
    leaked = caps & req.must_not_have
    if missing or leaked:
        parts = []
        if missing:
            parts.append(
                f"it requires {sorted(missing)}, which the zone does not provide"
            )
        if leaked:
            parts.append(
                f"the zone confers {sorted(leaked)}, which this component must not have"
            )
        raise IsolationError(
            f"{component} cannot run in {zone}: " + "; ".join(parts) + ". " + req.rationale
        )

    return {
        "component": component,
        "zone": zone,
        "granted": sorted(caps & (req.must_have | frozenset(
            {"artifact_decrypt", "finding_write", "telemetry_read", "intel_label",
             "envelope_read", "finding_read"}))),
        "denied": sorted(req.must_not_have),
        "rationale": req.rationale,
    }


def assert_separated(placement: dict[str, str]) -> None:
    """Refuse placements that put mutually dangerous components in one zone."""
    for a, b in SEPARATION_REQUIRED:
        if a in placement and b in placement and placement[a] == placement[b]:
            raise IsolationError(
                f"{a} and {b} must not share the {placement[a]!r} zone: "
                "co-residence defeats the isolation each depends on"
            )


def audit(placement: dict[str, str]) -> list[dict]:
    """Check a whole deployment, reporting every violation instead of the first."""
    violations: list[dict] = []

    for component in COMPONENTS:
        if component not in placement:
            violations.append({"rule": "unplaced", "component": component,
                               "why": "component has no zone: isolation was never decided"})

    for component, zone in placement.items():
        try:
            place(component, zone)
        except IsolationError as exc:
            violations.append({"rule": "placement", "component": component,
                               "zone": zone, "why": str(exc)})

    try:
        assert_separated(placement)
    except IsolationError as exc:
        violations.append({"rule": "separation", "why": str(exc)})

    return violations


def enforce(placement: dict[str, str]) -> None:
    violations = audit(placement)
    if violations:
        raise IsolationError(
            "\n".join(f"[{v['rule']}] {v.get('component', '')}: {v['why']}"
                      for v in violations)
        )


# --- data flow -----------------------------------------------------------

CIPHERTEXT = "ciphertext"
PLAINTEXT_ARTIFACT = "plaintext_artifact"
REDACTED_EXTRACT = "redacted_extract"
FINDING = "finding"
ENVELOPE = "envelope"
INTEL_LABEL = "intel_label"
OBSERVATION = "observation"
REPORT = "report"
KEY_MATERIAL = "key_material"

# Deny by default: anything not listed is refused.
ALLOWED_FLOWS: frozenset[tuple[str, str, str]] = frozenset({
    (INGEST, VAULT, CIPHERTEXT),
    (VAULT, ENCLAVE, CIPHERTEXT),
    (KEYSTORE, ENCLAVE, KEY_MATERIAL),
    (ENCLAVE, VAULT, FINDING),
    (ENCLAVE, VAULT, ENVELOPE),
    (ENCLAVE, AI, REDACTED_EXTRACT),
    (ENCLAVE, AI, FINDING),
    (VAULT, AI, FINDING),
    (VAULT, AI, ENVELOPE),
    (AI, ENCLAVE, OBSERVATION),
    (INTEL, ENCLAVE, INTEL_LABEL),
    (VAULT, PRESENTATION, FINDING),
    (VAULT, PRESENTATION, ENVELOPE),
    (PRESENTATION, VAULT, REPORT),
})


def may_flow(src_zone: str, dst_zone: str, kind: str) -> bool:
    return (src_zone, dst_zone, kind) in ALLOWED_FLOWS


def assert_flow(src_zone: str, dst_zone: str, kind: str) -> None:
    if may_flow(src_zone, dst_zone, kind):
        return
    if kind == PLAINTEXT_ARTIFACT:
        raise IsolationError(
            f"plaintext artifact may not flow {src_zone} -> {dst_zone}: decrypted "
            "evidence stays in the analysis enclave, and anything leaving carries "
            "graded findings or redacted extracts instead"
        )
    if kind == KEY_MATERIAL and dst_zone != ENCLAVE:
        raise IsolationError(
            f"key material may not flow to {dst_zone}: keys are unwrapped only inside "
            "the enclave, and never into a component that interprets attacker bytes "
            "or calls a model"
        )
    raise IsolationError(f"flow refused: {src_zone} -> {dst_zone} carrying {kind}")


# --- AI output grading ---------------------------------------------------


def ai_observation(statement: str, *, source: str = "model") -> F.Observation:
    """Wrap model output as an observation graded HYPOTHESIS.

    Never a Finding: a model that has read attacker-influenced text is an unreliable
    narrator about it, and prompt injection turns its conclusion into an input
    chosen by the adversary. Grading, benign alternatives and adjudication stay with
    a human, which is what rules F1 and F2 exist to force.
    """
    return F.Observation(
        statement=statement,
        plane="ai_assisted",
        grade=F.HYPOTHESIS,
        telemetry_gaps=("model_output_unverified",),
        source=source,
    )

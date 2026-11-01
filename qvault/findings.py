"""
qvault.findings
===============

Five mandatory rules, enforced by the type system rather than by reviewer goodwill.

The rules
---------
**F1  Every finding has an evidence grade.**
**F2  Every finding has at least one plausible benign explanation considered.**
**F3  Missing telemetry lowers confidence; it never silently becomes a clean result.**
**F4  Detection and attribution are separate.**
**F5  The tool never calls a device clean simply because no known spyware was found.**

Why they need to be structural
------------------------------
Each of these fails the same way in practice: a detector emits something, a human
reads it as a conclusion, and the missing half of the reasoning is invisible because
nobody was required to write it down. A rule in a document is a rule until the first
deadline. A constructor that raises is a rule that survives one.

So:

* `Finding` cannot be constructed without a grade and at least one benign
  explanation (F1, F2);
* confidence is *computed* from the grade minus declared telemetry gaps, and a
  caller that asserts a higher confidence than the computation allows is in
  violation rather than merely optimistic (F3);
* detection lives in `Observation` and attribution lives in `Attribution`, graded
  independently, with attribution capped by detection (F4);
* `DeviceAssessment.verdict` has no `clean` value to return, and a device with
  unobserved critical surfaces cannot reach the most favourable value at all (F5).

The status of a finding is derived, not chosen: an unexcluded benign explanation
caps it at `suspicious`, because "we could not rule out the boring explanation" is
not a finding of malice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- grades (same vocabulary as the claims ledger) ------------------------

CONFIRMED = "CONFIRMED"
CORROBORATED = "CORROBORATED"
INFERRED = "INFERRED"
HYPOTHESIS = "HYPOTHESIS"
UNKNOWN = "UNKNOWN"

GRADES = (CONFIRMED, CORROBORATED, INFERRED, HYPOTHESIS, UNKNOWN)
_RANK = {UNKNOWN: 0, HYPOTHESIS: 1, INFERRED: 2, CORROBORATED: 3, CONFIRMED: 4}

# --- benign explanations ---------------------------------------------------

RULED_OUT = "ruled_out"
PARTIALLY_EXCLUDED = "partially_excluded"
NOT_EXCLUDED = "not_excluded"
DISPOSITIONS = (RULED_OUT, PARTIALLY_EXCLUDED, NOT_EXCLUDED)

# --- finding status -------------------------------------------------------

OBSERVATION = "observation"
SUSPICIOUS = "suspicious"
MALICIOUS_INDICATED = "malicious_indicated"

# --- device verdicts (note what is absent) --------------------------------

NO_EVIDENCE_FOUND = "no_evidence_found"
INCONCLUSIVE = "inconclusive"
SUSPICIOUS_VERDICT = "suspicious"
MALICIOUS_VERDICT = "malicious_indicated"

#: Words that may never be emitted as a verdict (F5).
FORBIDDEN_VERDICTS = frozenset(
    {"clean", "clear", "trusted", "secure", "all_good", "no_threat", "no_issues"}
)

#: Rule identifiers, so a violation can be cited in a report.
R1, R2, R3, R4, R5 = "F1_no_grade", "F2_no_benign", "F3_gap_not_reflected", (
    "F4_attribution_exceeds_detection"
), "F5_clean_claim"


class FindingError(ValueError):
    """Raised when a finding cannot be constructed honestly."""


@dataclass(frozen=True)
class BenignExplanation:
    """A boring explanation that was actually considered, with its disposition."""

    description: str
    disposition: str
    reasoning: str

    def __post_init__(self) -> None:
        if self.disposition not in DISPOSITIONS:
            raise FindingError(f"unknown disposition {self.disposition!r}")
        if not self.description.strip() or not self.reasoning.strip():
            raise FindingError("a benign explanation needs both a description and reasoning")


def has_unexcluded_benign(explanations) -> bool:
    """True if any benign explanation survived scrutiny."""
    return any(e.disposition != RULED_OUT for e in explanations)


# --- F3: confidence is computed, never asserted ---------------------------


def confidence_grade(grade: str, telemetry_gaps=()) -> str:
    """Lower a grade by one step per declared telemetry gap.

    A gap is a surface that was not observed. It cannot leave confidence where it
    was, and it can never raise a finding into a clean result: the floor is
    `UNKNOWN`, which means "we do not know", not "nothing there".
    """
    if grade not in GRADES:
        raise FindingError(f"{R1}: unknown grade {grade!r}")
    rank = _RANK[grade] - len(list(telemetry_gaps))
    rank = max(0, min(rank, _RANK[CONFIRMED]))
    for name, value in _RANK.items():
        if value == rank:
            return name
    return UNKNOWN


@dataclass(frozen=True)
class Observation:
    """What was seen, on which plane, graded, with its blind spots declared."""

    statement: str
    plane: str
    grade: str
    telemetry_gaps: tuple[str, ...] = ()
    source: str = ""

    def __post_init__(self) -> None:
        if self.grade not in GRADES:
            raise FindingError(f"{R1}: observation has no valid evidence grade")
        if not self.statement.strip():
            raise FindingError("an observation needs a statement")

    @property
    def confidence(self) -> str:
        return confidence_grade(self.grade, self.telemetry_gaps)


@dataclass(frozen=True)
class Attribution:
    """Who or what is believed responsible. Separated from detection on purpose."""

    subject: str
    grade: str
    basis: str
    benign_explanations: tuple[BenignExplanation, ...] = ()

    def __post_init__(self) -> None:
        if self.grade not in GRADES:
            raise FindingError(f"{R1}: attribution has no valid evidence grade")
        if not self.basis.strip():
            raise FindingError("attribution needs a stated basis")

    @property
    def confidence(self) -> str:
        return self.grade


@dataclass
class Finding:
    """A graded observation, optionally attributed, with benign alternatives."""

    identifier: str
    observation: Observation
    benign_explanations: tuple[BenignExplanation, ...] = ()
    attribution: Attribution | None = None

    def __post_init__(self) -> None:
        if not self.benign_explanations:
            raise FindingError(
                f"{R2}: every finding must consider at least one plausible benign "
                "explanation, including the finding that says 'this is fine'"
            )
        if self.attribution is not None:
            if self.attribution.grade not in GRADES:
                raise FindingError(f"{R1}: attribution has no evidence grade")
            if _RANK[self.attribution.grade] > _RANK[self.observation.grade]:
                raise FindingError(
                    f"{R4}: attribution ({self.attribution.grade}) cannot exceed "
                    f"detection ({self.observation.grade}); you cannot be more certain "
                    "who did it than that it happened"
                )

    # -- derived properties ------------------------------------------------

    @property
    def detection_confidence(self) -> str:
        return confidence_grade(self.observation.grade, self.observation.telemetry_gaps)

    @property
    def benign_unexcluded(self) -> bool:
        return has_unexcluded_benign(self.benign_explanations) or (
            self.attribution is not None
            and has_unexcluded_benign(self.attribution.benign_explanations)
        )

    @property
    def status(self) -> str:
        """Derived, not chosen.

        An unexcluded benign explanation caps the finding at `suspicious`: not
        being able to rule out the boring explanation is not evidence of malice.
        """
        if self.attribution is None:
            return OBSERVATION
        if self.benign_unexcluded:
            return SUSPICIOUS
        if _RANK[self.attribution.grade] >= _RANK[CORROBORATED]:
            return MALICIOUS_INDICATED
        return SUSPICIOUS

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "status": self.status,
            "observation": {
                "statement": self.observation.statement,
                "plane": self.observation.plane,
                "grade": self.observation.grade,
                "confidence_after_gaps": self.detection_confidence,
                "telemetry_gaps": list(self.observation.telemetry_gaps),
                "source": self.observation.source,
            },
            "attribution": None
            if self.attribution is None
            else {
                "subject": self.attribution.subject,
                "grade": self.attribution.grade,
                "basis": self.attribution.basis,
                "benign_explanations": [
                    {
                        "description": b.description,
                        "disposition": b.disposition,
                        "reasoning": b.reasoning,
                    }
                    for b in self.attribution.benign_explanations
                ],
            },
            "benign_explanations": [
                {
                    "description": b.description,
                    "disposition": b.disposition,
                    "reasoning": b.reasoning,
                }
                for b in self.benign_explanations
            ],
        }


# --- F5: device-level verdicts -------------------------------------------


@dataclass
class DeviceAssessment:
    """A device-level conclusion that cannot say 'clean'."""

    device: str
    findings: list[Finding] = field(default_factory=list)
    surfaces_observed: tuple[str, ...] = ()
    surfaces_not_observed: tuple[str, ...] = ()
    critical_surfaces: tuple[str, ...] = ("firmware", "storage", "network")

    def __post_init__(self) -> None:
        overlap = set(self.surfaces_observed) & set(self.surfaces_not_observed)
        if overlap:
            raise FindingError(
                f"surfaces cannot be both observed and unobserved: {sorted(overlap)}"
            )

    @property
    def unobserved_critical(self) -> tuple[str, ...]:
        observed = set(self.surfaces_observed)
        return tuple(s for s in self.critical_surfaces if s not in observed)

    @property
    def verdict(self) -> str:
        """Computed. There is no branch that returns 'clean'."""
        if any(f.status == MALICIOUS_INDICATED for f in self.findings):
            return MALICIOUS_VERDICT
        if any(f.status == SUSPICIOUS for f in self.findings):
            return SUSPICIOUS_VERDICT
        if self.unobserved_critical:
            return INCONCLUSIVE
        return NO_EVIDENCE_FOUND

    def statement(self) -> str:
        """A phrasing that is true even when nothing was found."""
        observed = ", ".join(self.surfaces_observed) or "none"
        missing = ", ".join(self.surfaces_not_observed) or "none"
        base = (
            f"No evidence of compromise was found on the surfaces examined ({observed}). "
            f"Surfaces not examined: {missing}. "
        )
        if self.unobserved_critical:
            base += (
                "Because critical surfaces were not examined, this is not a clean "
                "result and must not be reported as one."
            )
        else:
            base += (
                "This states an absence of findings, not an absence of compromise."
            )
        return base

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "verdict": self.verdict,
            "surfaces_observed": list(self.surfaces_observed),
            "surfaces_not_observed": list(self.surfaces_not_observed),
            "unobserved_critical": list(self.unobserved_critical),
            "statement": self.statement(),
            "findings": [f.to_dict() for f in self.findings],
        }


# --- auditing findings that came from elsewhere --------------------------


def audit_finding(doc: dict) -> list[dict]:
    """Check an imported finding against F1-F5 without trusting its author.

    Used for findings produced by other tools, feeds or reports, where the point is
    to find violations rather than to raise on the first one.
    """
    violations: list[dict] = []

    def flag(rule: str, why: str) -> None:
        violations.append({"identifier": doc.get("identifier", "<unnamed>"), "rule": rule, "why": why})

    obs = doc.get("observation") or {}
    if obs.get("grade") not in GRADES:
        flag(R1, "observation has no evidence grade")

    benign = doc.get("benign_explanations") or []
    if not benign:
        flag(R2, "no benign explanation considered")

    gaps = obs.get("telemetry_gaps") or []
    claimed = obs.get("confidence_after_gaps") or obs.get("grade")
    if gaps and obs.get("grade") in GRADES and claimed in GRADES:
        allowed = _RANK[confidence_grade(obs["grade"], gaps)]
        if _RANK[claimed] > allowed:
            flag(R3, f"confidence {claimed} not reduced for {len(gaps)} telemetry gap(s)")

    att = doc.get("attribution")
    if att:
        if att.get("grade") not in GRADES:
            flag(R1, "attribution has no evidence grade")
        elif obs.get("grade") in GRADES and _RANK[att["grade"]] > _RANK[obs["grade"]]:
            flag(R4, "attribution grade exceeds detection grade")

    verdict = str(doc.get("verdict", "")).lower()
    if verdict in FORBIDDEN_VERDICTS:
        flag(R5, f"verdict {verdict!r} claims cleanliness")

    return violations


def observation_from_detector(identifier: str, statement: str, plane: str, source: str = "") -> Observation:
    """Wrap raw detector output as an observation, not a finding.

    Detector output is a claim that something was seen. It becomes a finding only
    when someone grades it and writes down what else could explain it, which is the
    whole point of F1 and F2.
    """
    return Observation(
        statement=statement,
        plane=plane,
        grade=INFERRED,
        telemetry_gaps=(),
        source=source or identifier,
    )

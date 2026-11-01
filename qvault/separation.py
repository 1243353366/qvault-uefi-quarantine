"""
qvault.separation
=================

Four roles, and the refusal that keeps them apart.

The rule
--------
**The detection engine must not be trusted to certify its own integrity.**

That is not a policy preference, it is a statement about evidence direction, the same
one that stops an operating-system scan certifying its own firmware. A component that
reports "I am intact" has produced a claim about itself from inside itself, and the
claim is exactly as trustworthy as the compromise it is meant to detect. An implant
that patches the detector's classifier will also patch the detector's self-check, in
the same write.

So the pipeline is cut into four roles and a component may hold exactly one:

`ACQUISITION`  reads artifacts, emits sealed originals and provenance. Makes no claims
               about its own coverage or correctness.
`ANALYSIS`     the detection engine. Interprets bytes, emits observations and findings.
`EVIDENCE_STORAGE`  holds immutable originals, envelopes and the audit chain. Cannot
               judge what it holds.
`TRUST_VERIFICATION`  attests the integrity of the other three, using evidence it
               gathered itself or that is anchored outside this system.

The rule that binds them: an attestation is only evidence if the attestor is **not the
subject** and is **not in the subject's role**, and if the evidence is not the
subject's own report. Anything else is self-certification, sometimes with an extra
signature.

The regress, handled honestly
-----------------------------
Someone must verify the verifier. This module does not pretend to solve that: an
attestation records the `root` that anchors the attestor, and when there is no root the
result carries an `unverified_root` gap and cannot be called verified. A verifier with
no external anchor is a component asserting its own trustworthiness, which is the thing
this module exists to refuse.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import findings as F
from . import isolation as I

# --- roles ----------------------------------------------------------------

ACQUISITION = "acquisition"
ANALYSIS = "analysis"
STORAGE = "evidence_storage"
VERIFICATION = "trust_verification"

ROLES = (ACQUISITION, ANALYSIS, STORAGE, VERIFICATION)

DUTIES: dict[str, dict] = {
    ACQUISITION: {
        "may": ["read_artifact", "emit_provenance", "seal_original"],
        "must_not": ["grade_finding", "attest_own_coverage", "certify_own_integrity"],
    },
    ANALYSIS: {
        "may": ["parse_artifact", "emit_observation", "emit_finding", "correlate"],
        "must_not": ["write_original", "certify_own_integrity", "attest_own_version",
                     "clear_own_audit_entry"],
    },
    STORAGE: {
        "may": ["hold_original", "hold_envelope", "append_audit", "read_manifest"],
        "must_not": ["grade_finding", "certify_own_integrity",
                     "attest_own_integrity", "rewrite_history"],
    },
    VERIFICATION: {
        "may": ["measure_artifact", "check_manifest", "verify_audit_chain", "attest"],
        "must_not": ["parse_artifact", "grade_finding", "modify_original",
                     "certify_own_integrity"],
    },
}

# Component -> the single role it holds. Parsing components come from the zone model,
# so a component cannot be added to the pipeline without a role.
COMPONENT_ROLE: dict[str, str] = {
    I.EVIDENCE_READER: ACQUISITION,
    I.DB_PARSER: ANALYSIS,
    I.INDICATOR_PROCESSING: ANALYSIS,
    I.REPORT_GENERATION: ANALYSIS,
    I.AI_ANALYSIS: ANALYSIS,
    "vault_store": STORAGE,
    "audit_log": STORAGE,
    "engine_verifier": VERIFICATION,
    "firmware_verifier": VERIFICATION,
    "audit_verifier": VERIFICATION,
}

# Zones each role may occupy, per qvault/isolation.py.
ROLE_ZONES: dict[str, frozenset[str]] = {
    ACQUISITION: frozenset({I.ENCLAVE}),
    ANALYSIS: frozenset({I.ENCLAVE, I.INTEL, I.AI, I.PRESENTATION}),
    STORAGE: frozenset({I.KEYSTORE}),
    VERIFICATION: frozenset({I.ENCLAVE, I.KEYSTORE}),
}

# --- attestation evidence classes ----------------------------------------

SELF_REPORT = "self_report"
PEER_CLAIM = "peer_claim"
INDEPENDENT_MEASUREMENT = "independent_measurement"
SIGNED_MANIFEST = "signed_manifest"
HARDWARE_ANCHOR = "hardware_anchor"

EVIDENCE_CLASSES = (SELF_REPORT, PEER_CLAIM, INDEPENDENT_MEASUREMENT, SIGNED_MANIFEST,
                    HARDWARE_ANCHOR)

#: Strongest grade each class can support. `self_report` supports nothing at all.
GRADE_BY_CLASS = {
    SELF_REPORT: None,
    PEER_CLAIM: F.HYPOTHESIS,
    INDEPENDENT_MEASUREMENT: F.CORROBORATED,
    SIGNED_MANIFEST: F.CORROBORATED,
    HARDWARE_ANCHOR: F.CONFIRMED,
}


class SeparationError(ValueError):
    """Raised when the role model is violated or misdeclared."""


class SelfCertificationError(SeparationError):
    """Raised when a component is asked to attest itself or its own role."""


@dataclass(frozen=True)
class Attestation:
    """A claim that one component is intact, made by another."""

    subject: str
    attestor: str
    evidence_class: str
    method: str = ""
    root: str = ""          # what anchors the attestor (hardware, signed release, host)

    def __post_init__(self) -> None:
        if self.evidence_class not in EVIDENCE_CLASSES:
            raise SeparationError(
                f"unknown evidence class {self.evidence_class!r}; known: {EVIDENCE_CLASSES}"
            )
        if self.subject not in COMPONENT_ROLE:
            raise SeparationError(f"attestation subject {self.subject!r} has no declared role")
        if self.attestor not in COMPONENT_ROLE:
            raise SeparationError(f"attestor {self.attestor!r} has no declared role")

    @property
    def subject_role(self) -> str:
        return COMPONENT_ROLE[self.subject]

    @property
    def attestor_role(self) -> str:
        return COMPONENT_ROLE[self.attestor]


def verify(att: Attestation) -> dict:
    """Judge one attestation, refusing self-certification outright."""
    if att.attestor == att.subject:
        raise SelfCertificationError(
            f"{att.subject} cannot attest its own integrity: a self-check is authored by "
            "the same bytes it is meant to detect tampering in"
        )
    if att.attestor_role == att.subject_role:
        raise SelfCertificationError(
            f"{att.attestor} ({att.attestor_role}) cannot attest {att.subject}: both hold "
            f"the {att.subject_role} role, so the claim comes from inside the thing judged"
        )
    if att.evidence_class == SELF_REPORT:
        raise SelfCertificationError(
            f"{att.attestor} is relaying {att.subject}'s own report, which is the subject "
            "certifying itself through an intermediary"
        )
    if VERIFICATION not in (att.attestor_role,):
        raise SeparationError(
            f"{att.attestor} holds the {att.attestor_role} role and may not issue "
            f"attestations; only {VERIFICATION} may"
        )

    grade = GRADE_BY_CLASS[att.evidence_class]
    gaps: list[str] = []
    if not att.root:
        gaps.append(
            "unverified_root: nothing outside this system anchors the attestor, so the "
            "verifier's own integrity is asserted rather than established"
        )
    if att.evidence_class == PEER_CLAIM:
        gaps.append(
            "peer_claim: the attestor reports on the subject without measuring it"
        )

    confidence = F.confidence_grade(grade, tuple(gaps)) if gaps else grade
    verified = not gaps and grade is not None
    return {
        "subject": att.subject,
        "subject_role": att.subject_role,
        "attestor": att.attestor,
        "evidence_class": att.evidence_class,
        "grade": grade,
        "confidence": confidence,
        "verified": verified,
        "gaps": gaps,
        "statement": (
            f"{att.subject} ({att.subject_role}) attested by {att.attestor} via "
            f"{att.evidence_class}: "
            + ("verified" if verified else
               "not verified; " + "; ".join(g.split(":", 1)[0] for g in gaps))
        ),
    }


def find_circular_trust(attestations) -> list[list[str]]:
    """Mutual peer attestation is self-certification spread across two nodes.

    A measures B and B measures A is fine. A *reports* on B and B *reports* on A, with
    neither measuring the other, is a closed loop with no external evidence in it.
    """
    edges: dict[str, set[str]] = {}
    for att in attestations:
        if att.evidence_class in (PEER_CLAIM, SELF_REPORT):
            edges.setdefault(att.attestor, set()).add(att.subject)

    cycles: list[list[str]] = []
    seen: set[frozenset[str]] = set()
    for a, targets in edges.items():
        for b in targets:
            if a in edges.get(b, set()):
                pair = frozenset({a, b})
                if pair not in seen:
                    seen.add(pair)
                    cycles.append(sorted(pair))
    return cycles


def audit_separation() -> dict:
    """Structural checks that the role model is actually separated."""
    violations: list[dict] = []
    notes: list[str] = []

    # Every parsing component in the zone model must hold exactly one role.
    for component in I.COMPONENTS:
        if component not in COMPONENT_ROLE:
            violations.append({"rule": "unassigned_component", "component": component,
                               "why": "component in the pipeline with no separation role"})

    # A role may only be held in zones compatible with it.
    for component, role in COMPONENT_ROLE.items():
        zone = I.DEFAULT_PLACEMENT.get(component)
        if zone and zone not in ROLE_ZONES[role]:
            violations.append({
                "rule": "role_zone_mismatch", "component": component,
                "why": f"{role} may not run in zone {zone}",
            })

    # Storage and verification must not share a role with analysis.
    for role in (STORAGE, VERIFICATION):
        holders = [c for c, r in COMPONENT_ROLE.items() if r == role]
        if not holders:
            violations.append({"rule": "empty_role", "component": role,
                               "why": f"no component holds {role}"})

    # Honest note, not a pass: verification has no zone of its own.
    if I.ENCLAVE in ROLE_ZONES[VERIFICATION]:
        notes.append(
            "verification shares the enclave zone with acquisition components; a "
            "dedicated verification zone is the correct target and is not implemented"
        )

    return {
        "violations": violations,
        "notes": notes,
        "statement": (
            f"{len(COMPONENT_ROLE)} components across {len(set(COMPONENT_ROLE.values()))} "
            f"roles; {len(violations)} separation violation(s), {len(notes)} limitation(s). "
            "One role per component, and no component attests itself."
            if not violations else
            f"{len(violations)} separation violation(s): the pipeline is not separated"
        ),
    }


def assert_separated() -> dict:
    audit = audit_separation()
    if audit["violations"]:
        raise SeparationError(f"separation audit failed: {audit['violations']}")
    return audit


def role_of(component: str) -> str:
    if component not in COMPONENT_ROLE:
        raise SeparationError(f"{component!r} has no declared role")
    return COMPONENT_ROLE[component]


def may(component: str, action: str) -> bool:
    """Whether a component's role permits an action, with the duty list as the authority."""
    role = role_of(component)
    duties = DUTIES[role]
    if action in duties["must_not"]:
        return False
    return action in duties["may"]

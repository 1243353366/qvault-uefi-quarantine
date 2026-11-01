"""Tests for qvault.findings — the five mandatory rules, enforced."""

from __future__ import annotations

import pytest

from qvault import findings as F
from qvault.findings import (
    Attribution, BenignExplanation, DeviceAssessment, Finding, FindingError, Observation,
)

RULED = lambda d="Windows Update": BenignExplanation(d, F.RULED_OUT, "checked: no update window open")
OPEN = lambda d="BITS transfer": BenignExplanation(d, F.NOT_EXCLUDED, "not investigated")


def obs(**kw) -> Observation:
    base = dict(statement="svchost NETSVCS fetched a binary", plane="live_state",
                grade=F.INFERRED, telemetry_gaps=())
    base.update(kw)
    return Observation(**base)


# --- F1: every finding has an evidence grade -----------------------------


def test_observation_without_a_valid_grade_is_rejected():
    with pytest.raises(FindingError) as e:
        Observation(statement="something happened", plane="live_state", grade="probably")
    assert F.R1 in str(e.value)


def test_attribution_without_a_grade_is_rejected():
    with pytest.raises(FindingError):
        Attribution(subject="MoonBounce", grade="", basis="looks like it")


def test_all_five_grades_are_accepted():
    for g in F.GRADES:
        assert obs(grade=g).grade == g


# --- F2: a benign explanation is mandatory -------------------------------


def test_finding_without_benign_explanation_cannot_exist():
    with pytest.raises(FindingError) as e:
        Finding(identifier="F-1", observation=obs())
    assert F.R2 in str(e.value)


def test_benign_explanation_needs_disposition_and_reasoning():
    with pytest.raises(FindingError):
        BenignExplanation("updates", "probably_fine", "n/a")
    with pytest.raises(FindingError):
        BenignExplanation("", F.RULED_OUT, "")


def test_an_unexcluded_benign_explanation_caps_status_at_suspicious():
    f = Finding(
        identifier="F-2",
        observation=obs(grade=F.CONFIRMED),
        benign_explanations=(OPEN(),),
        attribution=Attribution("MoonBounce", F.CONFIRMED, "hook signature in CORE_DXE"),
    )
    assert f.status == F.SUSPICIOUS
    assert f.benign_unexcluded is True


def test_ruling_out_the_benign_explanation_allows_malicious_status():
    f = Finding(
        identifier="F-3",
        observation=obs(grade=F.CONFIRMED),
        benign_explanations=(RULED(),),
        attribution=Attribution("MoonBounce", F.CONFIRMED, "hook signature in CORE_DXE"),
    )
    assert f.status == F.MALICIOUS_INDICATED


def test_partially_excluded_still_caps_at_suspicious():
    f = Finding(
        identifier="F-4",
        observation=obs(grade=F.CONFIRMED),
        benign_explanations=(BenignExplanation("updates", F.PARTIALLY_EXCLUDED, "partly checked"),),
        attribution=Attribution("MoonBounce", F.CONFIRMED, "signature"),
    )
    assert f.status == F.SUSPICIOUS


# --- F3: missing telemetry lowers confidence ----------------------------


def test_each_gap_lowers_confidence_by_one_step():
    assert F.confidence_grade(F.CONFIRMED) == F.CONFIRMED
    assert F.confidence_grade(F.CONFIRMED, ["firmware"]) == F.CORROBORATED
    assert F.confidence_grade(F.CONFIRMED, ["firmware", "network"]) == F.INFERRED
    assert F.confidence_grade(F.INFERRED, ["a", "b", "c", "d"]) == F.UNKNOWN


def test_gaps_never_raise_confidence():
    assert F.confidence_grade(F.HYPOTHESIS, []) == F.HYPOTHESIS
    assert F.confidence_grade(F.HYPOTHESIS, ["x"]) == F.UNKNOWN


def test_missing_firmware_telemetry_reduces_a_network_finding():
    f = Finding(
        identifier="F-5",
        observation=obs(grade=F.CORROBORATED, telemetry_gaps=("firmware",)),
        benign_explanations=(RULED(),),
    )
    assert f.observation.grade == F.CORROBORATED
    assert f.detection_confidence == F.INFERRED


# --- F4: detection and attribution are separate -------------------------


def test_attribution_cannot_exceed_detection():
    with pytest.raises(FindingError) as e:
        Finding(
            identifier="F-6",
            observation=obs(grade=F.INFERRED),
            benign_explanations=(RULED(),),
            attribution=Attribution("BlackLotus", F.CONFIRMED, "family attribution"),
        )
    assert F.R4 in str(e.value)


def test_observation_without_attribution_stays_an_observation():
    f = Finding(identifier="F-7", observation=obs(grade=F.CONFIRMED), benign_explanations=(RULED(),))
    assert f.status == F.OBSERVATION


def test_attribution_has_its_own_benign_explanations():
    f = Finding(
        identifier="F-8",
        observation=obs(grade=F.CONFIRMED),
        benign_explanations=(RULED(),),
        attribution=Attribution(
            "MoonBounce", F.CORROBORATED, "hook bytes at CORE_DXE .text",
            benign_explanations=(OPEN("vendor debug build"),),
        ),
    )
    # Detection benign reasoning is closed, attribution reasoning is not.
    assert f.status == F.SUSPICIOUS


def test_serialisation_keeps_detection_and_attribution_apart():
    f = Finding(
        identifier="F-9",
        observation=obs(grade=F.CORROBORATED, telemetry_gaps=("firmware",)),
        benign_explanations=(RULED(),),
        attribution=Attribution("LoJax", F.INFERRED, "module inventory diff"),
    )
    doc = f.to_dict()
    # CORROBORATED lowered one step for the declared firmware gap.
    assert doc["observation"]["confidence_after_gaps"] == F.INFERRED
    assert doc["attribution"]["grade"] == F.INFERRED
    assert doc["status"] == F.SUSPICIOUS   # INFERRED attribution cannot reach malicious


# --- F5: never call a device clean -------------------------------------


def test_clean_is_not_a_constructible_verdict():
    a = DeviceAssessment(
        device="ws-01",
        findings=[],
        surfaces_observed=("firmware", "storage", "network"),
        surfaces_not_observed=(),
    )
    assert a.verdict == F.NO_EVIDENCE_FOUND
    assert a.verdict not in F.FORBIDDEN_VERDICTS


def test_unobserved_critical_surface_forces_inconclusive():
    a = DeviceAssessment(
        device="ws-01",
        findings=[],
        surfaces_observed=("storage", "network"),
        surfaces_not_observed=("firmware",),
    )
    assert a.verdict == F.INCONCLUSIVE
    assert a.unobserved_critical == ("firmware",)


def test_no_evidence_found_requires_every_critical_surface_observed():
    partial = DeviceAssessment("ws-01", [], ("firmware", "storage"), ("network",))
    full = DeviceAssessment("ws-01", [], ("firmware", "storage", "network"), ())
    assert partial.verdict == F.INCONCLUSIVE
    assert full.verdict == F.NO_EVIDENCE_FOUND


def test_verdict_tracks_findings_upward():
    suspicious = Finding(
        identifier="F-10", observation=obs(grade=F.CONFIRMED), benign_explanations=(OPEN(),),
        attribution=Attribution("MoonBounce", F.CORROBORATED, "signature"),
    )
    a = DeviceAssessment("ws-01", [suspicious], ("firmware", "storage", "network"), ())
    assert a.verdict == F.SUSPICIOUS_VERDICT


def test_statement_admits_what_was_not_examined():
    a = DeviceAssessment("ws-01", [], ("storage",), ("firmware", "network"))
    text = a.statement()
    assert "firmware" in text
    assert "not a clean result" in text
    assert "absence of findings, not an absence of compromise" not in text


def test_statement_with_full_coverage_still_refuses_to_imply_health():
    a = DeviceAssessment("ws-01", [], ("firmware", "storage", "network"), ())
    assert "absence of findings, not an absence of compromise" in a.statement()


def test_surface_cannot_be_both_observed_and_unobserved():
    with pytest.raises(FindingError):
        DeviceAssessment("ws-01", [], ("firmware",), ("firmware",))


# --- auditing imported findings -----------------------------------------


def test_audit_flags_a_finding_with_no_grade_or_benign_reasoning():
    violations = F.audit_finding({"identifier": "X-1", "observation": {"statement": "bad"}})
    rules = {v["rule"] for v in violations}
    assert F.R1 in rules and F.R2 in rules


def test_audit_flags_unreduced_confidence_and_clean_verdict():
    doc = {
        "identifier": "X-2",
        "verdict": "clean",
        "observation": {"grade": F.CONFIRMED, "telemetry_gaps": ["firmware"],
                        "confidence_after_gaps": F.CONFIRMED},
        "benign_explanations": [{"description": "updates", "disposition": F.RULED_OUT,
                                 "reasoning": "checked"}],
        "attribution": {"subject": "X", "grade": F.CONFIRMED, "basis": "feed"},
    }
    rules = {v["rule"] for v in F.audit_finding(doc)}
    assert F.R3 in rules          # gap not reflected
    assert F.R5 in rules          # verdict claims cleanliness


def test_audit_passes_a_well_formed_finding():
    doc = Finding(
        identifier="F-11", observation=obs(grade=F.CORROBORATED, telemetry_gaps=()),
        benign_explanations=(RULED(),),
        attribution=Attribution("LoJax", F.CORROBORATED, "SecDxe present, NtfsDxe absent"),
    ).to_dict()
    doc["verdict"] = F.SUSPICIOUS_VERDICT
    assert F.audit_finding(doc) == []


def test_detector_output_is_an_observation_not_a_finding():
    o = F.observation_from_detector("netobs-1", "svchost fetched payload", "wire")
    assert isinstance(o, Observation)
    assert o.grade == F.INFERRED
    assert not isinstance(o, Finding)

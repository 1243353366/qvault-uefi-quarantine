"""Tests for qvault.isolation — zone placement for the five untrusted components."""

from __future__ import annotations

import pytest

from qvault import findings as F
from qvault import isolation as I
from qvault.isolation import IsolationError


# --- every named component is modelled -----------------------------------


def test_all_five_requested_components_are_modelled():
    assert set(I.COMPONENTS) == {
        "evidence_reader", "db_parser", "indicator_processing",
        "report_generation", "ai_analysis",
    }


def test_unknown_component_or_zone_is_rejected():
    with pytest.raises(IsolationError):
        I.place("my_script", I.ENCLAVE)
    with pytest.raises(IsolationError):
        I.place(I.EVIDENCE_READER, "laptop")


# --- the default placement is valid -------------------------------------


def test_default_placement_passes_audit():
    assert I.audit(I.DEFAULT_PLACEMENT) == []
    I.enforce(I.DEFAULT_PLACEMENT)


def test_each_component_gets_what_it_needs():
    r = I.place(I.EVIDENCE_READER, I.ENCLAVE)
    assert "artifact_read" in r["granted"]
    assert r["denied"]
    assert I.place(I.AI_ANALYSIS, I.AI)["zone"] == I.AI


# --- readers and parsers -------------------------------------------------


@pytest.mark.parametrize("component", [I.EVIDENCE_READER, I.DB_PARSER])
def test_readers_cannot_sit_where_a_model_is_reachable(component):
    with pytest.raises(IsolationError) as e:
        I.place(component, I.AI)
    assert "must not have" in str(e.value)


@pytest.mark.parametrize("component", [I.EVIDENCE_READER, I.DB_PARSER])
def test_readers_cannot_sit_in_the_reporting_zone(component):
    with pytest.raises(IsolationError):
        I.place(component, I.PRESENTATION)


def test_reader_needs_a_zone_that_can_read_artifacts():
    with pytest.raises(IsolationError) as e:
        I.place(I.EVIDENCE_READER, I.VAULT)
    assert "requires" in str(e.value)


# --- indicator processing ------------------------------------------------


def test_indicator_processing_cannot_write_findings():
    """Suppression is the quiet attack: no write access to detection state."""
    with pytest.raises(IsolationError) as e:
        I.place(I.INDICATOR_PROCESSING, I.ENCLAVE)
    msg = str(e.value)
    assert "finding_write" in msg or "artifact_read" in msg
    assert "suppression" in msg


def test_indicator_processing_cannot_read_raw_artifacts():
    with pytest.raises(IsolationError):
        I.place(I.INDICATOR_PROCESSING, I.ENCLAVE)


def test_indicator_processing_needs_intel_access():
    with pytest.raises(IsolationError):
        I.place(I.INDICATOR_PROCESSING, I.VAULT)


# --- report generation ---------------------------------------------------


def test_report_generation_never_touches_artifacts():
    with pytest.raises(IsolationError):
        I.place(I.REPORT_GENERATION, I.ENCLAVE)


def test_report_generation_needs_the_presentation_zone():
    assert I.place(I.REPORT_GENERATION, I.PRESENTATION)["zone"] == I.PRESENTATION


# --- AI analysis ---------------------------------------------------------


def test_ai_cannot_sit_in_the_analysis_enclave():
    with pytest.raises(IsolationError):
        I.place(I.AI_ANALYSIS, I.ENCLAVE)


def test_ai_cannot_reach_keys_or_write_findings():
    req = I.REQUIREMENTS[I.AI_ANALYSIS].must_not_have
    assert {"key_access", "finding_write", "artifact_decrypt"} <= req


def test_ai_output_is_an_observation_graded_hypothesis():
    o = I.ai_observation("this looks like MoonBounce because of the hook pattern")
    assert isinstance(o, F.Observation)
    assert not isinstance(o, F.Finding)
    assert o.grade == F.HYPOTHESIS
    assert "model_output_unverified" in o.telemetry_gaps
    # A gap lowers it further: a model claim is unknown until a human grades it.
    assert o.confidence == F.UNKNOWN


# --- separation ----------------------------------------------------------


def test_ai_and_a_reader_cannot_share_a_zone():
    with pytest.raises(IsolationError) as e:
        I.assert_separated({I.AI_ANALYSIS: "shared", I.EVIDENCE_READER: "shared"})
    assert "must not share" in str(e.value)


def test_report_and_reader_cannot_share_a_zone():
    with pytest.raises(IsolationError):
        I.assert_separated({I.REPORT_GENERATION: "shared", I.DB_PARSER: "shared"})


def test_separation_passes_when_zones_differ():
    I.assert_separated(I.DEFAULT_PLACEMENT)


# --- auditing a deployment ----------------------------------------------


def test_audit_reports_missing_components():
    violations = I.audit({I.EVIDENCE_READER: I.ENCLAVE})
    rules = {v["rule"] for v in violations}
    assert "unplaced" in rules
    assert len([v for v in violations if v["rule"] == "unplaced"]) == 4


def test_audit_reports_every_violation_not_just_the_first():
    bad = {
        I.EVIDENCE_READER: I.AI,          # model reachable
        I.DB_PARSER: I.PRESENTATION,      # reporting zone
        I.INDICATOR_PROCESSING: I.ENCLAVE,  # can suppress findings
        I.REPORT_GENERATION: I.ENCLAVE,   # reads artifacts
        I.AI_ANALYSIS: I.ENCLAVE,         # plaintext + finding writes
    }
    violations = I.audit(bad)
    assert len([v for v in violations if v["rule"] == "placement"]) == 5


def test_enforce_raises_with_all_violations_listed():
    with pytest.raises(IsolationError) as e:
        I.enforce({I.AI_ANALYSIS: I.ENCLAVE})
    assert "unplaced" in str(e.value)


# --- data flow -----------------------------------------------------------


def test_ciphertext_may_flow_into_the_enclave_but_plaintext_may_not_leave():
    assert I.may_flow(I.VAULT, I.ENCLAVE, I.CIPHERTEXT) is True
    assert I.may_flow(I.ENCLAVE, I.AI, I.PLAINTEXT_ARTIFACT) is False


def test_plaintext_to_ai_is_refused_with_a_reason():
    with pytest.raises(IsolationError) as e:
        I.assert_flow(I.ENCLAVE, I.AI, I.PLAINTEXT_ARTIFACT)
    assert "stays in the analysis enclave" in str(e.value)


def test_plaintext_to_reporting_is_refused():
    assert I.may_flow(I.ENCLAVE, I.PRESENTATION, I.PLAINTEXT_ARTIFACT) is False
    with pytest.raises(IsolationError):
        I.assert_flow(I.ENCLAVE, I.PRESENTATION, I.PLAINTEXT_ARTIFACT)


def test_key_material_flows_only_to_the_enclave():
    assert I.may_flow(I.KEYSTORE, I.ENCLAVE, I.KEY_MATERIAL) is True
    with pytest.raises(IsolationError) as e:
        I.assert_flow(I.KEYSTORE, I.AI, I.KEY_MATERIAL)
    assert "keys are unwrapped only inside the enclave" in str(e.value)


def test_ai_may_return_observations_and_read_findings():
    assert I.may_flow(I.AI, I.ENCLAVE, I.OBSERVATION) is True
    assert I.may_flow(I.VAULT, I.AI, I.FINDING) is True
    assert I.may_flow(I.ENCLAVE, I.AI, I.REDACTED_EXTRACT) is True


def test_indicator_labels_flow_only_inward():
    assert I.may_flow(I.INTEL, I.ENCLAVE, I.INTEL_LABEL) is True
    assert I.may_flow(I.ENCLAVE, I.INTEL, I.FINDING) is False


def test_unlisted_flow_is_denied_by_default():
    assert I.may_flow(I.AI, I.INGEST, I.CIPHERTEXT) is False
    with pytest.raises(IsolationError):
        I.assert_flow(I.AI, I.INGEST, I.CIPHERTEXT)


def test_no_flow_carries_plaintext_or_keys_into_ai_or_reporting():
    for src, dst, kind in I.ALLOWED_FLOWS:
        assert not (dst in (I.AI, I.PRESENTATION) and kind == I.PLAINTEXT_ARTIFACT)
        assert not (dst != I.ENCLAVE and kind == I.KEY_MATERIAL)

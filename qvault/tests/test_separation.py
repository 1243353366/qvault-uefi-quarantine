"""Tests for role separation and the ban on self-certification."""

from __future__ import annotations

import pytest

from qvault import findings as F
from qvault import isolation as I
from qvault import separation as S
from qvault.separation import Attestation, SelfCertificationError, SeparationError


# --- the structural model ------------------------------------------------


def test_every_pipeline_component_holds_a_role():
    for component in I.COMPONENTS:
        assert component in S.COMPONENT_ROLE, component


def test_each_component_holds_exactly_one_role():
    """COMPONENT_ROLE is a dict, so one role per key; assert the values are valid."""
    for component, role in S.COMPONENT_ROLE.items():
        assert role in S.ROLES, component


def test_roles_are_disjoint_by_construction():
    holders: dict[str, list[str]] = {}
    for component, role in S.COMPONENT_ROLE.items():
        holders.setdefault(role, []).append(component)
    assert set(holders) == set(S.ROLES)
    for role, components in holders.items():
        assert len(set(components)) == len(components), role


def test_separation_audit_passes_with_no_violations():
    audit = S.assert_separated()
    assert audit["violations"] == []


def test_audit_reports_that_verification_has_no_own_zone():
    notes = S.audit_separation()["notes"]
    assert any("dedicated verification zone" in n for n in notes)


def test_role_duties_forbid_self_certification_everywhere():
    for role in S.ROLES:
        assert "certify_own_integrity" in S.DUTIES[role]["must_not"], role


def test_analysis_may_not_write_originals_or_clear_its_audit_trail():
    for action in ("write_original", "clear_own_audit_entry"):
        assert S.may(S.I.INDICATOR_PROCESSING, action) is False


def test_storage_may_not_grade_findings():
    assert S.may("vault_store", "grade_finding") is False
    assert S.may("vault_store", "hold_original") is True


def test_verification_may_not_parse_artifacts():
    assert S.may("engine_verifier", "parse_artifact") is False
    assert S.may("engine_verifier", "measure_artifact") is True


def test_undeclared_component_has_no_role():
    with pytest.raises(SeparationError):
        S.role_of("my_new_parser")


# --- the refusal ---------------------------------------------------------


def test_a_component_cannot_attest_itself():
    att = Attestation(subject="engine_verifier", attestor="engine_verifier",
                      evidence_class=S.INDEPENDENT_MEASUREMENT, root="tpm")
    with pytest.raises(SelfCertificationError) as e:
        S.verify(att)
    assert "authored by the same bytes" in str(e.value)


def test_same_role_attestation_is_refused():
    """Two analysis components are still one role, so the claim is internal."""
    att = Attestation(subject=S.I.DB_PARSER, attestor=S.I.INDICATOR_PROCESSING,
                      evidence_class=S.INDEPENDENT_MEASUREMENT, root="tpm")
    with pytest.raises(SelfCertificationError) as e:
        S.verify(att)
    assert "both hold the analysis role" in str(e.value)


def test_relaying_the_subjects_own_report_is_refused():
    att = Attestation(subject=S.I.DB_PARSER, attestor="engine_verifier",
                      evidence_class=S.SELF_REPORT, root="tpm")
    with pytest.raises(SelfCertificationError) as e:
        S.verify(att)
    assert "through an intermediary" in str(e.value)


def test_only_the_verification_role_may_issue_attestations():
    att = Attestation(subject="vault_store", attestor=S.I.EVIDENCE_READER,
                      evidence_class=S.INDEPENDENT_MEASUREMENT, root="tpm")
    with pytest.raises(SeparationError) as e:
        S.verify(att)
    assert "may not issue attestations" in str(e.value)


# --- what a verifier can actually establish ------------------------------


def test_independent_measurement_with_a_root_verifies():
    att = Attestation(subject=S.I.DB_PARSER, attestor="engine_verifier",
                      evidence_class=S.INDEPENDENT_MEASUREMENT,
                      method="hashed the module bytes from the signed release",
                      root="hardware_anchor:boot-rom")
    out = S.verify(att)
    assert out["verified"] is True
    assert out["grade"] == F.CORROBORATED
    assert out["gaps"] == []


def test_hardware_anchor_reaches_confirmed():
    att = Attestation(subject="vault_store", attestor="engine_verifier",
                      evidence_class=S.HARDWARE_ANCHOR, root="tpm:pcr0-7")
    out = S.verify(att)
    assert out["grade"] == F.CONFIRMED
    assert out["verified"] is True


def test_no_root_means_unverified_and_gapped():
    """The regress: a verifier with no external anchor is asserting itself."""
    att = Attestation(subject=S.I.DB_PARSER, attestor="engine_verifier",
                      evidence_class=S.INDEPENDENT_MEASUREMENT)
    out = S.verify(att)
    assert out["verified"] is False
    assert any("unverified_root" in g for g in out["gaps"])
    assert out["confidence"] != out["grade"]      # F3 lowers it further
    assert "not verified" in out["statement"]


def test_peer_claim_is_capped_at_hypothesis():
    att = Attestation(subject="audit_log", attestor="engine_verifier",
                      evidence_class=S.PEER_CLAIM, root="signed_release:key-1")
    out = S.verify(att)
    assert out["grade"] == F.HYPOTHESIS
    assert any("peer_claim" in g for g in out["gaps"])
    assert out["verified"] is False


def test_unknown_evidence_class_is_rejected():
    with pytest.raises(SeparationError):
        Attestation(subject="vault_store", attestor="engine_verifier",
                    evidence_class="looks_fine_to_me")


def test_attesting_an_undeclared_subject_is_rejected():
    with pytest.raises(SeparationError):
        Attestation(subject="some_script", attestor="engine_verifier",
                    evidence_class=S.PEER_CLAIM)


# --- circularity ---------------------------------------------------------


def test_mutual_peer_claims_are_a_cycle():
    atts = [
        Attestation(subject="vault_store", attestor="audit_log", evidence_class=S.PEER_CLAIM),
        Attestation(subject="audit_log", attestor="vault_store", evidence_class=S.PEER_CLAIM),
    ]
    cycles = S.find_circular_trust(atts)
    assert len(cycles) == 1
    assert set(cycles[0]) == {"vault_store", "audit_log"}


def test_mutual_independent_measurement_is_not_a_cycle():
    """Each actually measured the other's bytes; that is evidence, not a loop."""
    atts = [
        Attestation(subject="vault_store", attestor="engine_verifier",
                    evidence_class=S.INDEPENDENT_MEASUREMENT, root="tpm"),
        Attestation(subject="engine_verifier", attestor="audit_verifier",
                    evidence_class=S.INDEPENDENT_MEASUREMENT, root="tpm"),
    ]
    assert S.find_circular_trust(atts) == []


# --- role/zone consistency ----------------------------------------------


def test_role_zones_match_the_isolation_placement():
    for component, role in S.COMPONENT_ROLE.items():
        zone = I.DEFAULT_PLACEMENT.get(component)
        if zone:
            assert zone in S.ROLE_ZONES[role], component


def test_a_component_placed_in_an_incompatible_zone_is_a_violation(monkeypatch):
    """Analysis is not permitted in the keystore, where key material lives."""
    monkeypatch.setitem(S.COMPONENT_ROLE, S.I.DB_PARSER, S.ANALYSIS)
    monkeypatch.setitem(I.DEFAULT_PLACEMENT, S.I.DB_PARSER, I.KEYSTORE)
    audit = S.audit_separation()
    assert any(v["rule"] == "role_zone_mismatch" for v in audit["violations"])
    with pytest.raises(SeparationError):
        S.assert_separated()

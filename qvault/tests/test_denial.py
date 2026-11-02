"""The denial model is only worth having if its weak cases stay in it."""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from qvault import denial as D
from qvault import findings as F

ROOT = Path(__file__).resolve().parents[2]
NAMES = {"deny_access", "deny_capability", "deny_execution"}


def test_the_model_has_exactly_the_three_postures():
    D.assert_complete()
    assert {p.name for p in D.POSTURES} == NAMES


def test_an_unknown_posture_is_refused():
    with pytest.raises(D.DenialError):
        D.assess("deny_everything", plane="hardware")


def test_an_unknown_plane_is_refused():
    with pytest.raises(D.DenialError, match="unknown plane"):
        D.assess("deny_access", plane="vibes")


def test_negative_corroboration_is_refused():
    with pytest.raises(D.DenialError):
        D.assess("deny_access", plane="external_key", corroborating_evidence=-1)


def test_every_posture_lists_at_least_three_non_claims():
    for posture in D.POSTURES:
        assert len(posture.does_not_stop) >= 3, posture.name


def test_every_posture_states_when_the_denial_ends():
    for posture in D.POSTURES:
        assert posture.restored_when.strip(), posture.name


def test_every_posture_states_its_availability_cost():
    for posture in D.POSTURES:
        assert posture.availability_cost.strip(), posture.name


def test_no_denial_claim_ever_reaches_confirmed():
    """CONFIRMED is for evidence. Inability is not observable, so it stops at CORROBORATED."""
    for posture in D.POSTURES:
        for plane in posture.admissible_planes:
            for evidence in range(0, 6):
                for enforced in (True, False):
                    grade = D.assess(posture.name, plane=plane, corroborating_evidence=evidence,
                                     enforced_by_target=enforced)["grade"]
                    assert grade != F.CONFIRMED, f"{posture.name}/{plane}/{evidence}"


def test_enforcement_inside_the_target_caps_at_inferred():
    result = D.assess("deny_execution", plane="in_band", corroborating_evidence=5,
                      enforced_by_target=True)
    assert result["grade"] == F.INFERRED
    assert "compromise of the host is a compromise of the control" in result["reason"]


def test_no_plane_at_all_grades_unknown():
    assert D.assess("deny_execution", plane="absent", corroborating_evidence=5)["grade"] == F.UNKNOWN


def test_a_hardware_plane_reaches_corroborated_with_three_observations():
    result = D.assess("deny_capability", plane="hardware", corroborating_evidence=3,
                      enforced_by_target=False)
    assert result["grade"] == F.CORROBORATED


def test_one_observation_stays_a_hypothesis_even_on_hardware():
    result = D.assess("deny_capability", plane="hardware", corroborating_evidence=1,
                      enforced_by_target=False)
    assert result["grade"] == F.HYPOTHESIS


def test_a_ceiling_is_a_limit_not_a_target():
    """A strong plane never lifts a weak observation count."""
    result = D.assess("deny_access", plane="external_key", corroborating_evidence=0,
                      enforced_by_target=False)
    assert result["ceiling"] == F.CORROBORATED
    assert result["grade"] == F.HYPOTHESIS


def test_an_external_plane_self_enforced_by_the_target_drops_to_inferred():
    result = D.assess("deny_execution", plane="supply_chain", corroborating_evidence=5,
                      enforced_by_target=True)
    assert result["grade"] == F.INFERRED


def test_deny_access_records_that_a_copied_key_ends_it():
    posture = D.BY_NAME["deny_access"]
    joined = " ".join(posture.does_not_stop)
    assert "already copied" in joined
    assert "not encrypted" in joined, "a bootkit needs no payload to decrypt"


def test_deny_execution_names_the_signed_but_hostile_case():
    joined = " ".join(D.BY_NAME["deny_execution"].does_not_stop)
    assert "signed" in joined and "malicious" in joined
    assert "nobody shipped" in joined


def test_deny_capability_names_its_enumeration_weakness():
    posture = D.BY_NAME["deny_capability"]
    assert "enumeration" in posture.load_bearing
    assert "did not think of" in " ".join(posture.does_not_stop)


def test_the_postures_are_not_interchangeable():
    claims = {p.name: p.denies for p in D.POSTURES}
    assert len(set(claims.values())) == 3
    ends = {p.restored_when for p in D.POSTURES}
    assert len(ends) == 3


def test_assert_complete_catches_a_posture_that_lost_its_non_claims(monkeypatch):
    stripped = dataclasses.replace(D.POSTURES[0], does_not_stop=("only one",))
    monkeypatch.setattr(D, "POSTURES", (stripped,) + D.POSTURES[1:])
    with pytest.raises(D.DenialError, match="non-claims"):
        D.assert_complete()


def test_assert_complete_catches_a_posture_with_no_expiry(monkeypatch):
    hollow = dataclasses.replace(D.POSTURES[1], restored_when="  ")
    monkeypatch.setattr(D, "POSTURES", (D.POSTURES[0], hollow, D.POSTURES[2]))
    with pytest.raises(D.DenialError, match="denial ends"):
        D.assert_complete()


def test_grades_come_from_the_shared_vocabulary():
    result = D.assess("deny_access", plane="external_key", corroborating_evidence=3)
    assert result["grade"] in F.GRADES
    assert result["proposed"] in F.GRADES
    assert {D.PLANE_CEILING[p] for p in D.PLANES} <= set(F.GRADES)


def test_the_rendered_page_carries_every_non_claim():
    page = (ROOT / "report" / "DENIAL_MODEL.md").read_text()
    for posture in D.POSTURES:
        for item in posture.does_not_stop:
            assert item in page, f"{posture.name} lost a non-claim from the report"


def test_the_composition_note_names_the_shared_plane_failure():
    flattened = " ".join(f"{a} {b}" for a, b in D.COMPOSITION).lower()
    assert "collapses" in flattened
    assert "kernel-level" in flattened

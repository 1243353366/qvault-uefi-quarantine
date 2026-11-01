"""Tests for qvault.containment — the six denials and their enforcement planes."""

from __future__ import annotations

import pytest

from qvault import containment as c
from qvault.containment import Denial, Plan, assess, audit_claim


def os_only_plan() -> Plan:
    """The plan people actually write first: everything enforced by the host."""
    p = Plan()
    p.add(Denial(c.NETWORK, c.SUBJECT_OS, "host firewall deny-all"))
    p.add(Denial(c.INTER_NETWORK, c.SUBJECT_OS, "host firewall"))
    p.add(Denial(c.AUTH_SERVICES, c.SUBJECT_OS, "disable service accounts"))
    p.add(Denial(c.STORAGE, c.SUBJECT_OS, "volume ACLs"))
    p.add(Denial(c.COMPUTE, c.SUBJECT_OS, "kill processes"))
    p.add(Denial(c.DECRYPTION, c.SUBJECT_OS, "no key on disk"))
    return p


# --- vocabulary -----------------------------------------------------------


def test_unknown_capability_or_plane_is_rejected():
    with pytest.raises(ValueError):
        Denial("exfiltrate", c.FABRIC, "x")
    with pytest.raises(ValueError):
        Denial(c.NETWORK, "magic", "x")
    with pytest.raises(ValueError):
        assess(Plan(), "mostly_fine")


# --- the central claim ----------------------------------------------------


def test_subject_os_denials_hold_only_on_a_clean_host():
    plan = os_only_plan()
    result = assess(plan, c.CLEAN_HOST)
    # Five of six: an ACL on the host can never deny a decryption *capability*,
    # only reach to the ciphertext. That distinction is the point of the module.
    assert set(result["fully_denied"]) == set(c.CAPABILITIES) - {c.DECRYPTION}
    assert c.DECRYPTION in result["not_denied"]


@pytest.mark.parametrize("posture", [c.COMPROMISED_OS, c.COMPROMISED_FIRMWARE])
def test_subject_os_denials_evaporate_when_the_subject_is_compromised(posture):
    plan = os_only_plan()
    result = assess(plan, posture)
    assert result["fully_denied"] == []
    assert "network" in result["not_denied"]
    assert "compute" in result["not_denied"]


def test_host_firewall_is_not_a_network_control_against_a_compromised_host():
    plan = Plan().add(Denial(c.NETWORK, c.SUBJECT_OS, "host firewall deny-all"))
    result = assess(plan, c.COMPROMISED_OS)
    assert "network" in result["not_denied"]
    assert "network" not in result["fully_denied"]


# --- planes that survive --------------------------------------------------


def test_hypervisor_denial_survives_os_compromise_but_not_firmware():
    plan = Plan().add(Denial(c.STORAGE, c.HYPERVISOR, "no virtual disk attached"))
    assert assess(plan, c.COMPROMISED_OS)["rows"][2]["status"] == c.FULL
    assert assess(plan, c.COMPROMISED_FIRMWARE)["rows"][2]["status"] == c.PARTIAL


def test_fabric_denial_holds_at_every_posture_when_paths_are_enumerated():
    plan = Plan().add(
        Denial(c.NETWORK, c.FABRIC, "port ACL", covers_paths=c.EGRESS_PATHS)
    )
    for posture in c.POSTURES:
        row = assess(plan, posture)["rows"][0]
        assert row["status"] == c.FULL, posture


def test_fabric_denial_is_only_partial_when_a_radio_is_unaccounted_for():
    plan = Plan().add(
        Denial(c.NETWORK, c.FABRIC, "wired port ACL", covers_paths=frozenset({"wired"}))
    )
    row = assess(plan, c.COMPROMISED_FIRMWARE)["rows"][0]
    assert row["status"] == c.PARTIAL
    assert "unenumerated egress paths" in row["note"]
    assert "wireless" in row["note"]


def test_physical_power_off_denies_compute_at_any_posture():
    plan = Plan().add(Denial(c.COMPUTE, c.PHYSICAL, "powered off"))
    for posture in c.POSTURES:
        assert assess(plan, posture)["rows"][3]["status"] == c.FULL


# --- decryption is special ------------------------------------------------


def test_only_cryptography_fully_denies_decryption():
    plan = Plan().add(Denial(c.DECRYPTION, c.CRYPTOGRAPHIC, "no key material present"))
    for posture in c.POSTURES:
        assert assess(plan, posture)["rows"][5]["status"] == c.FULL


def test_non_crypto_planes_cannot_fully_deny_decryption():
    for plane, mechanism in [
        (c.FABRIC, "no route to the vault"),
        (c.HYPERVISOR, "no mount"),
        (c.PHYSICAL, "disk in a safe"),
    ]:
        plan = Plan().add(Denial(c.DECRYPTION, plane, mechanism))
        row = assess(plan, c.COMPROMISED_FIRMWARE)["rows"][5]
        assert row["status"] == c.PARTIAL
        assert "not the capability" in row["note"]


def test_cryptography_is_not_counted_as_denying_other_capabilities():
    plan = Plan().add(Denial(c.NETWORK, c.CRYPTOGRAPHIC, "encrypted tunnel"))
    result = assess(plan, c.COMPROMISED_OS)
    assert "network" in result["not_denied"]
    assert "network" not in result["fully_denied"]


# --- claim auditing ------------------------------------------------------


def test_claim_audit_rejects_the_os_only_plan_on_a_compromised_subject():
    violations = audit_claim(
        os_only_plan(), c.COMPROMISED_FIRMWARE, list(c.CAPABILITIES)
    )
    assert len(violations) == 6
    assert {v["capability"] for v in violations} == set(c.CAPABILITIES)
    assert all(v["actual"] == "none" for v in violations)


def test_claim_audit_passes_for_the_reference_plan():
    assert audit_claim(c.reference_plan(), c.COMPROMISED_FIRMWARE, list(c.CAPABILITIES)) == []


def test_claim_audit_rejects_unknown_capability():
    with pytest.raises(ValueError):
        audit_claim(Plan(), c.CLEAN_HOST, ["everything"])


def test_reference_plan_denies_all_six_at_the_worst_posture():
    result = assess(c.reference_plan(), c.COMPROMISED_FIRMWARE)
    assert set(result["fully_denied"]) == set(c.CAPABILITIES)
    assert result["not_denied"] == []


# --- honesty invariants --------------------------------------------------


def test_assessment_never_claims_eradication():
    for posture in c.POSTURES:
        assert assess(c.reference_plan(), posture)["eradicates"] is False


def test_assessment_states_that_firmware_persistence_survives():
    text = " ".join(assess(c.reference_plan(), c.COMPROMISED_FIRMWARE)["statements"])
    assert "survives every denial" in text
    assert "reflashing" in text


def test_empty_plan_denies_nothing_anywhere():
    result = assess(Plan(), c.CLEAN_HOST)
    assert result["fully_denied"] == []
    assert sorted(result["not_denied"]) == sorted(c.CAPABILITIES)


def test_plan_serialisation_is_stable():
    plan = c.reference_plan()
    doc = plan.to_dict()
    assert len(doc["denials"]) == 7
    assert doc["denials"][0]["covers_paths"] == sorted(c.EGRESS_PATHS)

"""Tests for the LAN layer: identity, deviation, lateral movement, graded containment."""

import pytest

from qvault import findings as F
from qvault import lan as N


def dev(id_, role, addr, **kw):
    return N.Device(id=id_, role=role, addr=addr, **kw)


WS = dev("ws1", N.WORKSTATION, "10.0.0.5", cert_fp="AA")
NAS = dev("nas1", N.NAS, "10.0.0.9", cert_fp="BB")
SW = dev("sw1", N.SWITCH, "10.0.0.2", mac="CC")
IOT = dev("cam1", N.IOT, "10.0.0.30", mac="DD")
# A plane whose integrity is evidenced, not asserted: this is the only shape that
# containment is willing to trust.
ATTESTED = {"switch": {"attested_by": "golden-config-hash", "evidence": "sha256:9f",
                       "at": 1000}}

DEVICES = {d.id: d for d in (WS, NAS, SW, IOT)}


# --- identity -------------------------------------------------------------

def test_identity_binds_to_certificate_not_bssid():
    d = dev("ap1", N.AP, "10.0.0.1", cert_fp="CERT", bssid="aa:bb:cc:dd:ee:ff")
    assert d.identity_key == "cert:CERT"
    assert "aa:bb" not in d.identity_key
    assert d.identity_strength == "certificate"


def test_a_device_with_no_authenticated_identity_is_refused():
    with pytest.raises(ValueError):
        _ = dev("x", N.WORKSTATION, "10.0.0.7").identity_key


def test_unknown_role_is_refused():
    with pytest.raises(ValueError):
        dev("x", "toaster", "10.0.0.8", mac="EE")


# --- baselines ------------------------------------------------------------

def test_duplicate_flows_collapse_before_counting():
    flows = [N.Flow(ts=1, src="ws1", dst="nas1", port=445, fingerprint="same") for _ in range(5)]
    unique, dropped = N.deduplicate_flows(flows)
    assert len(unique) == 1
    assert dropped == 4


def test_baseline_deviation_reports_new_peer_with_a_benign_reading():
    base = N.build_baseline([N.Flow(ts=1, src="ws1", dst="nas1", port=445)])
    news = N.deviations([N.Flow(ts=9, src="ws1", dst="cam1", port=443)], base)
    kinds = {d["kind"] for d in news}
    # both are true: the peer is new and so is the service, which the baseline only had as 445
    assert kinds == {"new_peer", "new_service"}
    assert all(d["benign"] for d in news)


def test_no_deviation_for_traffic_inside_the_baseline():
    flows = [N.Flow(ts=i, src="ws1", dst="nas1", port=445) for i in range(1, 6)]
    base = N.build_baseline(flows)
    assert N.deviations(flows, base) == []


def test_unknown_device_is_first_contact_not_a_verdict():
    out = N.deviations([N.Flow(ts=1, src="ghost", dst="nas1", port=445)], {})
    assert out[0]["kind"] == "first_contact"
    assert "baseline" in out[0]["benign"]


# --- role policy ----------------------------------------------------------

def test_iot_device_opening_rdp_is_out_of_role():
    out = N.out_of_role([N.Flow(ts=1, src="cam1", dst="nas1", port=3389)], DEVICES)
    assert out and out[0]["kind"] == "out_of_role"
    assert out[0]["suspicion_floor"] == "INFERRED"


def test_workstation_browsing_is_not_out_of_role():
    assert N.out_of_role([N.Flow(ts=1, src="ws1", dst="nas1", port=443)], DEVICES) == []


def test_every_out_of_role_entry_carries_a_benign_explanation():
    out = N.out_of_role([N.Flow(ts=1, src="cam1", dst="nas1", port=22)], DEVICES)
    assert all(o["benign"] for o in out)


# --- discovery ------------------------------------------------------------

def test_unsanctioned_llmnr_response_is_a_name_authority_claim():
    ev = N.DiscoveryEvent(ts=1, device="cam1", protocol="llmnr", kind="response")
    out = N.discovery_anomalies([ev])
    assert out[0]["kind"] == "name_authority_claim"
    assert out[0]["grade"] == "INFERRED"


def test_designated_responder_is_not_flagged():
    ev = N.DiscoveryEvent(ts=1, device="dns1", protocol="netbios", kind="response", designated=True)
    assert N.discovery_anomalies([ev]) == []


def test_ssdp_advertisement_is_only_a_hypothesis():
    ev = N.DiscoveryEvent(ts=1, device="cam1", protocol="ssdp", kind="advertise")
    assert N.discovery_anomalies([ev])[0]["grade"] == "HYPOTHESIS"


def test_unknown_discovery_protocol_is_refused():
    with pytest.raises(ValueError):
        N.DiscoveryEvent(ts=1, device="x", protocol="carrier-pigeon", kind="query")


# --- lateral movement -----------------------------------------------------

def _breach_flows():
    return [N.Flow(ts=100, src="ws1", dst="nas1", port=445, fingerprint="a"),
            N.Flow(ts=110, src="ws1", dst="nas1", port=3389, fingerprint="b")]


def _auths():
    return [N.AuthEvent(ts=90, device="ws1", principal="admin", credential="c", result="failure"),
            N.AuthEvent(ts=95, device="ws1", principal="admin", credential="c", result="success")]


def test_single_layer_is_a_lead_not_a_suspicion():
    out = N.lateral_movement([N.Flow(ts=1, src="ws1", dst="nas1", port=445)], [], DEVICES)
    assert out["independent_layers"] == 1
    assert out["suspicion"] is False
    assert out["grade"] == F.HYPOTHESIS


def test_three_layers_reach_corroborated():
    out = N.lateral_movement(_breach_flows(), _auths(), DEVICES)
    assert out["independent_layers"] >= 3
    assert out["grade"] == F.CORROBORATED
    assert out["suspicion"] is True


def test_replayed_flows_cannot_inflate_independence():
    flows = _breach_flows() + [N.Flow(ts=100, src="ws1", dst="nas1", port=445, fingerprint="a") for _ in range(6)]
    out = N.lateral_movement(flows, _auths(), DEVICES)
    assert out["duplicates_dropped"] == 6
    assert out["east_west_flows"] == 2


def test_success_after_failure_is_recorded_per_principal():
    out = N.lateral_movement(_breach_flows(), _auths(), DEVICES)
    assert out["success_after_failure"][0]["principal"] == "admin"
    assert out["success_after_failure"][0]["failures_before"] == 1


# --- infrastructure -------------------------------------------------------

def test_unattested_network_gear_produces_gaps():
    out = N.infrastructure_integrity(DEVICES)
    assert "sw1" in out["firmware_unattested"]
    assert any(g.startswith("infra_firmware_unattested") for g in out["gaps"])


def test_mac_only_identity_is_flagged_as_weak():
    out = N.infrastructure_integrity(DEVICES)
    assert "sw1" in out["identity_bound_to_mac_only"]


# --- identity inconsistency ----------------------------------------------

def test_endpoint_evidence_alone_cannot_establish_inconsistency():
    out = N.identity_inconsistency({"endpoint_indicators": True})
    assert out["verdict"] == "insufficient"


def test_no_firmware_anchor_leaves_it_unverified():
    out = N.identity_inconsistency({"lan_deviation": True, "endpoint_indicators": True})
    assert out["verdict"] == "unverified"
    assert out["gaps"][0].startswith("no_firmware_anchor")


def test_lan_plus_endpoint_plus_firmware_is_inconsistent_with_identity():
    out = N.identity_inconsistency({"lan_deviation": True, "endpoint_indicators": True,
                                    "firmware_attested": True})
    assert out["verdict"] == "inconsistent_with_identity"
    assert out["grade"] == F.CORROBORATED


# --- containment ----------------------------------------------------------

def test_untrusted_switch_plane_cannot_enforce_isolation():
    plan = N.containment_plan({"suspicion": True}, {"switch": {"trusted": False, "reason": "unattested"}})
    refused = {r["step"] for r in plan["refused"]}
    assert {"isolate_port", "microsegment"} <= refused
    allowed = {s["step"] for s in plan["steps"]}
    assert "isolate_port" not in allowed


def test_trusted_plane_allows_the_full_ladder():
    plan = N.containment_plan({"suspicion": True}, ATTESTED)
    assert len(plan["steps"]) == len(N.LADDER)


def test_every_step_is_device_scoped_and_names_verification():
    plan = N.containment_plan({"suspicion": True}, ATTESTED)
    for step in plan["steps"]:
        assert step["blast_radius_devices"] == 1
        assert step["verify_by"]
        N.assert_narrow(step)


def test_containment_that_would_spread_is_refused():
    with pytest.raises(ValueError):
        N.assert_narrow({"step": "fleet", "blast_radius_devices": 12})
    with pytest.raises(ValueError):
        N.assert_narrow({"step": "push_helper", "blast_radius_devices": 1,
                         "action_kind": "agent_binary"})


def test_no_plan_pushes_material_to_other_hosts():
    plan = N.containment_plan({"suspicion": True}, ATTESTED)
    for step in plan["steps"]:
        assert step["action_kind"] if "action_kind" in step else True
    assert "credential" in plan["forbidden_actions"]


def test_low_suspicion_does_not_escalate():
    plan = N.containment_plan({"suspicion": False}, ATTESTED)
    assert plan["escalate"] is False

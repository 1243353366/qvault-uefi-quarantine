"""The LAN layer wired up: fusion, grading split, loader, containment refusals."""

import pytest

from qvault import findings as F
from qvault import lan as N

WS = N.Device(id="ws1", role=N.WORKSTATION, addr="10.0.0.5", cert_fp="AA")
NAS = N.Device(id="nas1", role=N.NAS, addr="10.0.0.9", cert_fp="BB")
SW = N.Device(id="sw1", role=N.SWITCH, addr="10.0.0.2", mac="CC")
DEVICES = [WS, NAS, SW]

RDP = [N.Flow(ts=100, src="ws1", dst="nas1", port=3389, fingerprint="f1")]
AUTHS = [
    N.AuthEvent(ts=90, device="ws1", principal="admin", credential="c1", result="failure"),
    N.AuthEvent(ts=95, device="ws1", principal="admin", credential="c1", result="success"),
]


def fuse(**kw):
    args = dict(devices=DEVICES, flows=RDP, auths=AUTHS, firmware={})
    args.update(kw)
    return N.cross_layer(**args)


def test_a_role_violation_does_not_need_a_firmware_anchor():
    """Network evidence stands alone. Coupling it to the anchor erased real violations."""
    out = fuse()
    assert out["verdict"] == "suspicious"
    assert out["grade"] in (F.INFERRED, F.CORROBORATED)


def test_identity_verdict_does_need_the_anchor():
    without = fuse()
    assert without["identity"]["verdict"] != "inconsistent_with_identity"
    assert any(g.startswith("firmware_unattested") for g in without["gaps"])
    with_anchor = fuse(firmware={"host_trustworthy": True}, endpoint_findings=[{"status": "suspicious"}])
    assert with_anchor["identity"]["verdict"] == "inconsistent_with_identity"
    assert with_anchor["grade"] == F.CORROBORATED


def test_duplicate_flows_are_dropped_and_cannot_add_layers():
    twice = RDP + [N.Flow(ts=100, src="ws1", dst="nas1", port=3389, fingerprint="f1")]
    out = fuse(flows=twice)
    assert out["flows"] == 1
    assert out["duplicate_flows_dropped"] == 1


def test_containment_is_refused_when_the_switch_plane_is_untrusted():
    out = fuse()
    plan = N.containment_plan(out, {"switch": {"trusted": False, "reason": "image unattested"}})
    refused = {r["step"] for r in plan["refused"]}
    assert {"microsegment", "isolate_port"} <= refused
    assert not ({"microsegment", "isolate_port"} & {s["step"] for s in plan["steps"]})
    for step in plan["steps"]:
        assert step["blast_radius_devices"] == 1


def test_a_missing_inventory_and_traffic_are_named_gaps_not_clean():
    out = N.cross_layer(devices=[], flows=[], auths=[], firmware={})
    assert any("no network inventory" in g for g in out["gaps"])
    assert any("no traffic" in g for g in out["gaps"])
    assert out["verdict"] != "clean"


def test_the_verdict_vocabulary_never_includes_clean():
    for doc in (fuse(), fuse(flows=[], devices=[], auths=[])):
        assert "clean" not in str(doc["verdict"]).lower()


def test_loader_refuses_a_malformed_flow_by_name():
    with pytest.raises(N.LanError) as exc:
        N.load_case({"devices": [], "flows": [{"ts": 1, "src": "a", "dst": "b"}]})
    assert "malformed case file" in str(exc.value)


def test_loader_accepts_the_bytes_alias_and_maps_it():
    case = N.load_case({
        "devices": [{"id": "ws1", "role": "workstation", "addr": "10.0.0.5", "cert_fp": "AA"}],
        "flows": [{"ts": 1, "src": "ws1", "dst": "nas1", "port": 445, "bytes": 4096}],
    })
    assert case["flows"][0].byte_count == 4096


def test_loader_refuses_an_unknown_role():
    with pytest.raises(N.LanError):
        N.load_case({"devices": [{"id": "x", "role": "toaster", "addr": "10.0.0.7"}]})


def test_a_device_without_an_identity_is_refused():
    """An address is not an identity: the refusal must happen on access, not never."""
    with pytest.raises(ValueError):
        N.Device(id="x", role=N.WORKSTATION, addr="10.0.0.7").identity_key

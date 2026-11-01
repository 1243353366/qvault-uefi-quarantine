"""Tests for qvault.netobs — synthetic records only, no live captures."""

from __future__ import annotations

import json

import pytest

from qvault import netobs
from qvault.netobs import DnsEvent, FlowEvent, ProcessNode


def flow(**kw) -> FlowEvent:
    base = dict(
        ts=1000.0,
        host="ws-01",
        src_ip="10.0.0.5",
        dst_ip="93.184.216.34",  # genuinely external; 203.0.113.0/24 is documentation
        dst_port=443,
        bytes_out=500,
        bytes_in=900,
        image="chrome.exe",
    )
    base.update(kw)
    return FlowEvent(**base)


def wire(**kw) -> FlowEvent:
    base = dict(
        ts=1000.4,
        host="ws-01",
        src_ip="10.0.0.5",
        dst_ip="93.184.216.34",
        dst_port=443,
        bytes_out=500,
        bytes_in=900,
        source="wire",
        tier=netobs.WIRE_ONLY,
    )
    base.update(kw)
    return FlowEvent(**base)


# --- destination classification -------------------------------------------


@pytest.mark.parametrize(
    "ip,scope",
    [
        ("127.0.0.1", "internal"),
        ("10.1.2.3", "internal"),
        ("192.168.1.10", "internal"),
        ("172.16.5.4", "internal"),
        ("169.254.1.1", "internal"),
        ("fe80::1", "internal"),
        ("fd00::1", "internal"),
        ("8.8.8.8", "external"),
        ("2606:4700::1111", "external"),
        ("0.0.0.0", "special"),
        ("224.0.0.1", "special"),
        ("192.0.2.5", "special"),
        ("2001:db8::5", "special"),
    ],
)
def test_classify_scope_is_deterministic(ip, scope):
    out = netobs.classify_destination(ip)
    assert out["scope"] == scope
    assert out["scope_confidence"] == "deterministic"
    assert out["label_confidence"] == "none"


def test_cgnat_is_flagged_as_shared_attribution():
    out = netobs.classify_destination("100.64.7.7")
    assert out["scope"] == "special"
    assert "carrier-grade NAT" in out["reason"]


def test_invalid_address_is_unknown_not_guessed():
    out = netobs.classify_destination("not-an-ip")
    assert out["scope"] == "unknown"
    assert out["reason"] == "not an IP address"


def test_feed_labels_are_marked_separately_from_scope():
    out = netobs.classify_destination(
        "93.184.216.34", organization="Example CDN", category="cdn",
        feed="vendor-x", feed_age_days=3,
    )
    assert out["scope"] == "external"
    assert out["label_confidence"] == "feed"
    assert out["feed"] == "vendor-x"
    assert out["feed_age_days"] == 3


# --- correlation ----------------------------------------------------------


def test_agreement_produces_no_findings():
    assert netobs.correlate([flow()], [wire()]) == []


def test_wire_only_flow_is_high_severity():
    findings = netobs.correlate([], [wire()])
    assert [f.kind for f in findings] == ["unattributed_egress"]
    assert findings[0].severity == "high"


def test_host_only_flow_is_a_phantom_claim():
    findings = netobs.correlate([flow()], [])
    assert [f.kind for f in findings] == ["phantom_claim"]
    assert findings[0].severity == "high"


def test_conflicting_image_is_detected():
    findings = netobs.correlate([flow(image="winlogon.exe")], [wire(image="svchost.exe")])
    assert [f.kind for f in findings] == ["attribution_conflict"]
    assert findings[0].evidence["host_image"] == "winlogon.exe"
    assert findings[0].evidence["wire_image"] == "svchost.exe"


def test_egress_the_wire_never_carried_is_a_conflict():
    findings = netobs.correlate([flow(bytes_out=4096)], [wire(bytes_out=0)])
    assert [f.kind for f in findings] == ["attribution_conflict"]


def test_volume_disagreement_is_medium_not_high():
    findings = netobs.correlate([flow(bytes_out=10000)], [wire(bytes_out=1000)])
    assert [f.kind for f in findings] == ["volume_mismatch"]
    assert findings[0].severity == "medium"


def test_tolerance_excludes_a_late_observation():
    findings = netobs.correlate([flow(ts=1000.0)], [wire(ts=1100.0)], tolerance_s=2.0)
    kinds = sorted(f.kind for f in findings)
    assert kinds == ["phantom_claim", "unattributed_egress"]


def test_tier_assignment_marks_conflict_and_corroborated():
    findings = netobs.correlate([flow(image="winlogon.exe")], [wire(image="svchost.exe")])
    assert netobs.tier_for(flow(image="winlogon.exe"), findings) == netobs.CONFLICT
    assert netobs.tier_for(flow(), []) == netobs.CORROBORATED


# --- beaconing ------------------------------------------------------------


def test_beacon_score_regular_schedule():
    times = [1000 + 60 * i for i in range(8)]
    out = netobs.beacon_score(times)
    assert out["verdict"] == "regular"
    assert out["score"] >= 0.9
    assert out["n_intervals"] == 7


def test_beacon_score_tolerates_moderate_jitter():
    intervals = [60, 66, 54, 60, 63, 57, 61]
    times = [1000.0]
    for i in intervals:
        times.append(times[-1] + i)
    out = netobs.beacon_score(times)
    assert out["verdict"] == "regular"
    assert 0.4 < out["score"] <= 1.0


def test_beacon_score_irregular_traffic():
    intervals = [5, 300, 20, 900, 40, 700]
    times = [1000.0]
    for i in intervals:
        times.append(times[-1] + i)
    out = netobs.beacon_score(times)
    assert out["verdict"] == "irregular"
    assert out["score"] < 0.4


def test_beacon_score_refuses_to_conclude_on_thin_data():
    out = netobs.beacon_score([1000, 1060, 1120])
    assert out["verdict"] == "insufficient_data"
    assert out["score"] is None


def test_beacon_score_handles_duplicate_timestamps():
    out = netobs.beacon_score([1000, 1000, 1000, 1000, 1000])
    assert out["verdict"] in {"invalid", "irregular"}


# --- minimisation and evidence -------------------------------------------


def test_minimise_strips_query_strings_and_lowercases_names():
    f = flow(uri="https://example.test/a/b?token=SECRET&x=1")
    m = netobs.minimise(f)
    assert m["uri"] == "https://example.test/a/b"
    assert "SECRET" not in json.dumps(m)

    d = DnsEvent(ts=1.0, host="ws-01", qname="API.Example.TEST.")
    assert netobs.minimise(d)["qname"] == "api.example.test."


def test_minimise_never_emits_payload_fields():
    m = netobs.minimise(flow())
    for forbidden in ("payload", "body", "headers", "cookies", "query"):
        assert forbidden not in m


def test_evidence_serialisation_is_deterministic_regardless_of_order():
    records = [
        flow(ts=1000.0, dst_ip="198.51.100.1", dst_port=80),
        DnsEvent(ts=999.5, host="ws-01", qname="b.test"),
        ProcessNode(pid=4, image="C:/Windows/System32/winlogon.exe"),
        flow(ts=1000.25, dst_ip="198.51.100.2", dst_port=8080),
    ]
    a = netobs.to_evidence(records)
    b = netobs.to_evidence(list(reversed(records)))
    assert a == b
    doc = json.loads(a)
    assert doc["schema"] == "qvault.netobs.v1"
    assert all("ts_ms" in r for r in doc["records"] if "qname" in r or "dst_ip" in r)


# --- documented-family rules ---------------------------------------------


def test_winlogon_external_egress_fires_and_internal_does_not():
    ext = netobs.evaluate_rules([flow(image="C:/Windows/System32/winlogon.exe")])
    assert [f.kind for f in ext] == ["blacklotus_winlogon_egress"]

    internal = netobs.evaluate_rules(
        [flow(image="winlogon.exe", dst_ip="10.0.0.9", dst_port=135)]
    )
    assert internal == []


def test_documented_c2_path_fires():
    f = flow(uri="https://cdn.example.test/API/hpb_gate.php")
    assert [x.kind for x in netobs.evaluate_rules([f])] == ["blacklotus_gate_path"]


def test_moonbounce_netsvcs_shape_fires_only_with_inbound_bytes():
    hit = flow(image="svchost.exe", cmdline="SVCHOST.EXE -K NETSVCS -P", bytes_in=70000)
    assert [x.kind for x in netobs.evaluate_rules([hit])] == ["moonbounce_netsvcs_fetch"]

    no_inbound = flow(image="svchost.exe", cmdline="SVCHOST.EXE -K NETSVCS", bytes_in=0)
    assert netobs.evaluate_rules([no_inbound]) == []


def test_lojax_agent_rule_only_for_external_destination():
    assert [x.kind for x in netobs.evaluate_rules([flow(image="rpcnetp.exe")])] == [
        "lojax_agent_egress"
    ]
    assert netobs.evaluate_rules([flow(image="rpcnetp.exe", dst_ip="10.0.0.7")]) == []


def test_ipify_probe_requires_winlogon_attribution():
    d = DnsEvent(ts=1.0, host="ws-01", qname="api.ipify.org", image="winlogon.exe")
    assert [x.kind for x in netobs.evaluate_rules([], [d])] == ["blacklotus_ip_probe"]

    other = DnsEvent(ts=1.0, host="ws-01", qname="api.ipify.org", image="chrome.exe")
    assert netobs.evaluate_rules([], [other]) == []

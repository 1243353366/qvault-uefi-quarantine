"""Plane errors: trusting a plane the attacker may control.

An oracle error leaks an answer; a pilot error blocks an operator; a plane error makes
both worse, because the operator acts on evidence produced by the party being
investigated. These tests pin the three places that could happen here.
"""
import pathlib

import pytest

from qvault import correlate as C
from qvault import findings as F
from qvault import lan as N
from qvault import verify


def ev(ts, plane, kind=C.CONTACT, collector=""):
    return C.Event(ts=ts, subject="host-a", kind=kind, plane=plane,
                   grade=F.CORROBORATED, collector=collector)


def test_unattributed_planes_cannot_corroborate():
    """Three labels with no named collector are one claim, not three sources."""
    out = C.assess_cluster([ev(1, "wire"), ev(2, "live_state"), ev(3, "historical_record")])
    assert out["independent_planes"] == 1
    assert out["planes_unattributed"] is True
    assert out["raised"] is False
    assert out["grade"] == F.INFERRED


def test_one_collector_wearing_three_labels_is_one_plane():
    out = C.assess_cluster([
        ev(1, "wire", collector="sensor-1"),
        ev(2, "live_state", collector="sensor-1"),
        ev(3, "historical_record", collector="sensor-1"),
    ])
    assert out["independent_planes"] == 1
    assert out["raised"] is False


def test_distinct_collectors_are_independent():
    out = C.assess_cluster([
        ev(1, "wire", kind=C.INSTALL, collector="sensor-1"),
        ev(2, "live_state", kind=C.EXECUTION, collector="edr-2"),
        ev(3, "historical_record", kind=C.CONTACT, collector="db-3"),
    ])
    assert out["independent_planes"] == 3
    assert out["raised"] is True


def test_one_unattributed_plane_presumes_nothing():
    out = C.assess_cluster([ev(1, "wire", collector="sensor-1"),
                            ev(2, "live_state", collector="")])
    assert out["independent_planes"] == 1
    assert out["raised"] is False


@pytest.mark.parametrize("plane", [
    {},
    {"switch": {"trusted": True}},
    {"switch": {"attested_by": "self", "evidence": "x", "at": 1}},
    {"switch": {"trusted": False, "reason": "same image as the compromised AP"}},
    {"switch": {"attested_by": "golden-hash"}},
])
def test_a_plane_is_trusted_only_with_attestation(plane):
    ok, why = N._plane_attested(plane.get("switch", {}))
    assert not ok and why


def test_attested_plane_permits_the_switch_dependent_steps():
    ok, why = N._plane_attested({"attested_by": "golden-config-hash",
                                 "evidence": "sha256:9f", "at": 1000})
    assert ok and "golden-config-hash" in why
    plan = N.containment_plan({"suspicion": True},
                              {"switch": {"attested_by": "golden-config-hash",
                                          "evidence": "sha256:9f", "at": 1000}})
    assert len(plan["steps"]) == len(N.LADDER)
    assert plan["refused"] == []


def test_the_vault_verdict_names_its_own_plane():
    report = verify.VerifyReport()
    payload = report.to_dict()
    assert payload["attestation"] == "host_only"
    assert "host-derived" in verify.HOST_DERIVED
    assert "consistency" in verify.HOST_DERIVED


def test_the_licence_metadata_and_file_agree():
    root = pathlib.Path(__file__).resolve().parents[2]
    declared = (root / "pyproject.toml").read_text()
    text = (root / "LICENSE").read_text()
    assert "Apache-2.0" in declared
    assert "Apache License" in text and "Version 2.0" in text
    assert "MIT License" not in text
    assert len(text) > 10000


def test_the_sdist_carries_what_reproduction_needs():
    root = pathlib.Path(__file__).resolve().parents[2]
    manifest = (root / "MANIFEST.in").read_text()
    for needed in ("report", "tools", "requirements-lock.txt", "LICENSE"):
        assert needed in manifest

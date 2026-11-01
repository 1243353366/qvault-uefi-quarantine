"""Tests for qvault.limitations — the four architectural limitations as a model."""

from __future__ import annotations

import pytest

from qvault import limitations as L


# --- limitation 2: firmware blind spots -----------------------------------


def test_os_level_scan_cannot_establish_firmware_integrity_against_an_adversary():
    r = L.establish(L.P_FIRMWARE_INTEGRITY, [L.FIRMWARE_VIA_OS], adversarial=True)
    assert r["status"] == "supported"          # it says something...
    assert r["confidence"] == "low"
    assert r["adversarial_confidence"] == "none"   # ...but nothing usable
    assert L.FIRMWARE_OOB in r["would_need"]


def test_out_of_band_acquisition_does_support_the_claim():
    r = L.establish(L.P_FIRMWARE_INTEGRITY, [L.FIRMWARE_OOB], adversarial=True)
    assert r["adversarial_confidence"] == "high"
    assert r["best_plane"] == L.FIRMWARE_OOB


def test_combining_os_and_out_of_band_keeps_the_stronger_plane():
    r = L.establish(
        L.P_FIRMWARE_INTEGRITY, [L.FIRMWARE_VIA_OS, L.FIRMWARE_OOB], adversarial=True
    )
    assert r["adversarial_confidence"] == "high"
    assert set(r["supporting_planes"]) == {L.FIRMWARE_VIA_OS, L.FIRMWARE_OOB}


def test_out_of_band_requires_physical_access():
    assert L.PROFILES[L.FIRMWARE_OOB].requires_physical is True
    assert L.PROFILES[L.FIRMWARE_VIA_OS].requires_physical is False


def test_historical_records_cannot_establish_firmware_integrity():
    r = L.establish(L.P_FIRMWARE_INTEGRITY, [L.HISTORICAL, L.LIVE_STATE])
    assert r["status"] == "unsupported"
    assert "firmware_out_of_band" in r["caveats"][0]


# --- limitation 1: live state ---------------------------------------------


def test_live_state_cannot_support_an_adversarial_claim():
    r = L.audit_claim(L.P_PROCESS_EXISTED, [L.LIVE_STATE])
    assert r["defensible"] is False
    assert any("forgeable" in c for c in r["caveats"])


def test_live_state_is_still_useful_about_a_cooperative_system():
    r = L.establish(L.P_PROCESS_EXISTED, [L.LIVE_STATE], adversarial=False)
    assert r["confidence"] == "low"
    assert r["status"] == "supported"


def test_wire_evidence_is_not_forgeable_by_the_endpoint():
    r = L.establish(L.P_NETWORK_CONTACT, [L.WIRE], adversarial=True)
    assert r["adversarial_confidence"] == "high"
    assert L.PROFILES[L.WIRE].forgeable_by_subject is False


def test_live_and_wire_together_beat_live_alone():
    live_only = L.establish(L.P_NETWORK_CONTACT, [L.HISTORICAL], adversarial=True)
    both = L.establish(L.P_NETWORK_CONTACT, [L.HISTORICAL, L.WIRE], adversarial=True)
    assert live_only["adversarial_confidence"] == "none"
    assert both["adversarial_confidence"] == "high"


# --- limitation 3: baselines ----------------------------------------------


def test_baseline_after_compromise_is_poisoned():
    r = L.baseline_validity(captured_at=2000.0, compromise_window_start=1000.0)
    assert r["status"] == "poisoned"
    assert "certifies attacker behaviour as normal" in r["action"]


def test_baseline_before_compromise_is_valid():
    r = L.baseline_validity(captured_at=500.0, compromise_window_start=1000.0)
    assert r["status"] == "valid"


def test_unknown_compromise_window_is_unverified_never_valid():
    r = L.baseline_validity(captured_at=999.0)
    assert r["status"] == "unverified"
    assert "implant already resident" in r["reason"]


def test_baseline_cannot_establish_normality_against_an_adversary():
    r = L.establish(L.P_BEHAVIOUR_NORMAL, [L.BASELINE], adversarial=True)
    assert r["adversarial_confidence"] == "none"


# --- limitation 4: indicator trust ----------------------------------------


def test_three_feeds_one_upstream_is_circular_not_corroboration():
    feeds = [
        L.IntelFeed("feed-a", upstream="vendor-x", age_days=10, validated_independently=True),
        L.IntelFeed("feed-b", upstream="vendor-x", age_days=10, validated_independently=True),
        L.IntelFeed("feed-c", upstream="vendor-x", age_days=10, validated_independently=True),
    ]
    r = L.intel_trust(feeds)
    assert r["standing"] == "circular"
    assert r["distinct_upstreams"] == 1
    assert r["supports_malicious_claim"] is False
    assert "repetition, not corroboration" in r["caveats"][0]


def test_two_independent_upstreams_corroborate():
    feeds = [
        L.IntelFeed("feed-a", upstream="vendor-x", age_days=5, validated_independently=True),
        L.IntelFeed("feed-b", upstream="cert-y", age_days=5, validated_independently=True),
    ]
    r = L.intel_trust(feeds)
    assert r["standing"] == "corroborated"
    assert r["supports_malicious_claim"] is True


def test_single_source_is_flagged():
    r = L.intel_trust([L.IntelFeed("feed-a", upstream="vendor-x", age_days=5)])
    assert r["standing"] == "single_source"
    assert r["supports_malicious_claim"] is False


def test_stale_and_provenance_free_feeds_are_flagged():
    feeds = [
        L.IntelFeed("old", upstream="vendor-x", age_days=800, validated_independently=True),
        L.IntelFeed("anon", upstream="vendor-y", age_days=2, has_provenance=False),
    ]
    r = L.intel_trust(feeds)
    assert "old" in r["stale"]
    assert any("no provenance" in c for c in r["caveats"])


def test_no_feeds_supports_nothing():
    r = L.intel_trust([])
    assert r["supports_malicious_claim"] is False
    assert r["standing"] == "none"


def test_intel_alone_is_not_defensible_against_an_adversary():
    r = L.audit_claim(L.P_OBJECT_MALICIOUS, [L.INTEL])
    assert r["defensible"] is False


# --- registry integrity ---------------------------------------------------


def test_registry_covers_all_four_limitations_with_controls_and_residuals():
    assert len(L.LIMITATIONS) == 4
    for item in L.LIMITATIONS:
        assert item["limitation"] and item["consequence"] and item["control"]
        assert item["buys"] and item["cannot_buy"] and item["residual"]


def test_unknown_proposition_or_plane_is_rejected():
    with pytest.raises(ValueError):
        L.establish("everything_is_fine", [L.WIRE])
    with pytest.raises(ValueError):
        L.establish(L.P_NETWORK_CONTACT, ["vibes"])

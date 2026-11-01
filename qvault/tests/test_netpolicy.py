"""Tests for qvault.netpolicy — selection logic and the key-material boundary."""

from __future__ import annotations

import hashlib

import pytest

from qvault import netpolicy
from qvault.netpolicy import NetworkContext, select_policy

CORP_BSSID = "00:1a:2b:3c:4d:5e"  # globally administered, unicast
RANDOMISED = "02:1a:2b:3c:4d:5e"  # locally administered bit set


def managed_ctx(**kw) -> NetworkContext:
    base = dict(
        bssid=CORP_BSSID,
        ssid="corp-wifi",
        security="wpa2-eap",
        eap_server_validated=True,
        gateway_mac="00:1a:2b:3c:4d:5f",
        dhcp_domain="corp.example",
        expected_domain="corp.example",
        seen_before=True,
        registry_trust="managed",
    )
    base.update(kw)
    return NetworkContext(**base)


# --- address handling -----------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("00:1A:2B:3C:4D:5E", "00:1a:2b:3c:4d:5e"),
        ("00-1a-2b-3c-4d-5e", "00:1a:2b:3c:4d:5e"),
        ("  00:1a:2b:3c:4d:5e  ", "00:1a:2b:3c:4d:5e"),
    ],
)
def test_normalise_accepts_common_forms(value, expected):
    assert netpolicy.normalise_bssid(value) == expected


@pytest.mark.parametrize("bad", ["", None, "00:1a:2b:3c:4d", "zz:1a:2b:3c:4d:5e", "not-a-bssid"])
def test_normalise_rejects_invalid_without_raising(bad):
    assert netpolicy.normalise_bssid(bad) is None


def test_flags_identify_randomised_and_invalid():
    assert netpolicy.bssid_flags(CORP_BSSID)["locally_administered"] is False
    assert netpolicy.bssid_flags(RANDOMISED)["locally_administered"] is True
    assert netpolicy.bssid_flags("FF:FF:FF:FF:FF:FF")["multicast"] is True
    assert netpolicy.bssid_flags("nonsense")["valid"] is False


# --- the central rule: BSSID can never raise trust -----------------------


def test_bssid_alone_never_earns_managed_policy():
    """Registered as managed, but nothing else is right. Must not be authoritative."""
    d = select_policy(
        NetworkContext(bssid=CORP_BSSID, ssid="corp-wifi", registry_trust="managed")
    )
    assert d.trust != netpolicy.MANAGED
    assert d.policy == "untrusted"


def test_shared_psk_network_is_never_managed():
    d = select_policy(managed_ctx(security="wpa2-psk", eap_server_validated=None))
    assert d.trust == netpolicy.UNTRUSTED
    assert "no server-authenticated network identity" in d.reasons[0]


def test_eap_without_server_validation_is_untrusted():
    d = select_policy(managed_ctx(eap_server_validated=False))
    assert d.trust == netpolicy.UNTRUSTED
    assert any("evil-twin" in r for r in d.reasons)
    assert d.fail_safe is True


def test_randomised_bssid_falls_to_untrusted_even_with_managed_eap():
    d = select_policy(managed_ctx(bssid=RANDOMISED))
    assert d.trust == netpolicy.UNTRUSTED
    assert any("randomised" in r for r in d.reasons)


def test_invalid_bssid_fails_safe():
    d = select_policy(NetworkContext(bssid=None, security="wpa2-eap", eap_server_validated=True))
    assert d.trust == netpolicy.UNTRUSTED
    assert d.fail_safe is True


# --- corroboration --------------------------------------------------------


def test_fully_corroborated_network_is_managed():
    d = select_policy(managed_ctx())
    assert d.trust == netpolicy.MANAGED
    assert d.policy == "managed"
    assert d.settings["custody"] == (2, 3)
    assert d.settings["collection"] == "standard"
    assert len(d.corroborating_factors) >= 2


def test_missing_corroboration_downgrades_to_ambiguous():
    d = select_policy(
        managed_ctx(gateway_mac=None, dhcp_domain=None, expected_domain=None, seen_before=None)
    )
    assert d.trust == netpolicy.AMBIGUOUS
    assert d.policy == "ambiguous"
    assert d.settings["collection"] == "minimal"
    assert d.settings["allow_egress"] is False


def test_unknown_registry_downgrades_even_with_other_signals():
    d = select_policy(managed_ctx(registry_trust="unknown"))
    assert d.trust == netpolicy.AMBIGUOUS


def test_contradictory_dhcp_domain_is_not_resolved_in_favour_of_acceptance():
    d = select_policy(managed_ctx(dhcp_domain="evil.example"))
    assert d.trust == netpolicy.AMBIGUOUS
    assert any("contradicts" in r for r in d.reasons)


# --- hostility ------------------------------------------------------------


def test_hostile_network_preserves_more_evidence_not_less():
    d = select_policy(managed_ctx(registry_trust="hostile"))
    assert d.policy == "hostile"
    assert d.settings["collection"] == "forensic"
    assert d.settings["retention_days"] > netpolicy.POLICIES["managed"]["retention_days"]
    assert d.settings["allow_egress"] is False
    assert d.settings["custody"] == (3, 5)


def test_every_policy_seals_before_write():
    for name, p in netpolicy.POLICIES.items():
        assert p["seal_before_write"] is True, f"{name} would write plaintext first"


def test_no_policy_relies_on_a_single_custodian():
    for name, p in netpolicy.POLICIES.items():
        k, n = p["custody"]
        assert k >= 2 and n > k, f"{name} custody threshold is degenerate"


# --- the key-material boundary -------------------------------------------


def test_bssid_is_not_secret_and_must_not_seed_keys():
    """Two independent hosts 'deriving' from a BSSID land on identical bytes.

    This test exists to document the vulnerability, not to endorse the pattern.
    Anything a passive observer already knows cannot contribute secrecy.
    """
    def pretend_derive(bssid: str, host: str) -> bytes:
        return hashlib.sha256(bssid.encode()).digest()

    a = pretend_derive(CORP_BSSID, "host-a")
    b = pretend_derive(CORP_BSSID, "host-b")
    assert a == b, "if this ever differs, the demonstration no longer holds"


def test_decision_dict_carries_the_reasoning():
    d = select_policy(managed_ctx())
    doc = d.to_dict()
    for key in ("policy", "trust", "reasons", "corroborating_factors", "fail_safe",
                "collection", "retention_days", "custody", "seal_before_write"):
        assert key in doc


def test_envelope_context_records_that_context_did_not_make_a_key():
    ctx = managed_ctx()
    d = select_policy(ctx)
    env = netpolicy.envelope_context(ctx, d)
    assert env["schema"] == "qvault.netpolicy.v1"
    assert env["bssid"] == CORP_BSSID
    assert env["bssid_flags"]["locally_administered"] is False
    assert "did not contribute to any key" in env["note"]
    assert env["reasons"]

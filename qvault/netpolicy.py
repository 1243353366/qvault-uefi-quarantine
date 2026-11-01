"""
qvault.netpolicy
================

Network context as a *policy selector*. Not as key material, ever.

The idea
--------
An observed association (BSSID, SSID, security mode) plus corroborating evidence
selects which collection, retention and key-custody policy applies to evidence
gathered while on that network. This is the same shape as enterprise Wi-Fi
profiles keyed on SSID or EAP realm, and it is legitimate.

Why the BSSID must never be key material
----------------------------------------
A BSSID is 48 bits, transmitted in the clear in every beacon and probe response,
and it is trivially observed from outside the building and trivially cloned.
Deriving, seeding or "strengthening" a key with it produces a key that every
nearby radio already knows. `tests/test_netpolicy.py` demonstrates this directly:
two independent hosts that hash the same BSSID land on identical bytes.

The BSSID's only sound role is *selection*: it chooses a policy, and the key for
that policy comes from a CSPRNG on the host, tagged with the policy id.

Why selection has to be fail-safe
---------------------------------
The BSSID is attacker-controlled in the air. An evil-twin AP chooses the BSSID it
presents, so "we are on the office network" is a claim by whoever is radiating.
Therefore:

* the BSSID alone can never *raise* trust;
* raising trust requires an authenticated network (EAP with server certificate
  validation) **and** at least one independent corroborating factor;
* anything unknown, conflicting or randomised falls to the most restrictive
  policy, never the least;
* a hostile network is not "deny everything" - it is "preserve the most evidence
  under the tightest custody", because the whole point is to keep the case.

This module decides collection depth, retention and custody thresholds. It never
authorises key release: see `qvault/retrieve.py` and report THREAT_MODEL_REVIEW.md
W1 for why that separation matters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

BSSID_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$")

# Trust levels, ordered by how much they may relax a control.
MANAGED = "managed"
AMBIGUOUS = "ambiguous"
UNTRUSTED = "untrusted"
HOSTILE = "hostile"

EAP_MODES = {"wpa2-eap", "wpa3-eap", "wpa3-192", "eap-tls", "peap", "eap-ttls"}

POLICIES: dict[str, dict] = {
    "managed": {
        "collection": "standard",
        "retention_days": 90,
        "custody": (2, 3),
        "require_attestation": False,
        "allow_egress": True,
        "seal_before_write": True,
        "rationale": "authenticated network with corroborated identity",
    },
    "ambiguous": {
        "collection": "minimal",
        "retention_days": 7,
        "custody": (3, 5),
        "require_attestation": True,
        "allow_egress": False,
        "seal_before_write": True,
        "rationale": "identity claimed but not corroborated; treat as unknown",
    },
    "untrusted": {
        "collection": "minimal",
        "retention_days": 7,
        "custody": (3, 5),
        "require_attestation": True,
        "allow_egress": False,
        "seal_before_write": True,
        "rationale": "no server-authenticated network identity",
    },
    "hostile": {
        "collection": "forensic",
        "retention_days": 365,
        "custody": (3, 5),
        "require_attestation": True,
        "allow_egress": False,
        "seal_before_write": True,
        "rationale": "network previously recorded as hostile: preserve maximum evidence",
    },
}


def normalise_bssid(value: str | None) -> str | None:
    """Return a lowercase colon-separated BSSID, or None if invalid.

    Invalid is not an exception here: an unreadable BSSID is a normal condition
    (wired link, monitor mode, malformed association) and must fall through to a
    restrictive policy rather than crash a collector.
    """
    if not value:
        return None
    v = value.strip().lower().replace("-", ":")
    if not BSSID_RE.match(v):
        return None
    return v


def bssid_flags(value: str | None) -> dict:
    """Structural facts about a BSSID, computed from the address itself."""
    norm = normalise_bssid(value)
    if norm is None:
        return {"valid": False, "locally_administered": None, "multicast": None}
    first = int(norm[0:2], 16)
    return {
        "valid": True,
        "locally_administered": bool(first & 0x02),
        "multicast": bool(first & 0x01),
    }


@dataclass(frozen=True)
class NetworkContext:
    """What the collector observed, and what it can corroborate.

    `registry_trust` is the prior for this BSSID out of band (asset inventory,
    previous incident). It is a prior, not proof: the BSSID can be cloned, so the
    registry only ever contributes corroboration, never authorisation.
    """

    bssid: str | None
    ssid: str | None = None
    security: str = "unknown"
    eap_server_validated: bool | None = None
    gateway_mac: str | None = None
    dhcp_domain: str | None = None
    expected_domain: str | None = None
    seen_before: bool | None = None
    registry_trust: str = "unknown"  # unknown | managed | hostile


@dataclass
class Decision:
    policy: str
    trust: str
    reasons: list[str] = field(default_factory=list)
    corroborating_factors: list[str] = field(default_factory=list)
    fail_safe: bool = False

    @property
    def settings(self) -> dict:
        return dict(POLICIES[self.policy])

    def to_dict(self) -> dict:
        d = {
            "policy": self.policy,
            "trust": self.trust,
            "reasons": self.reasons,
            "corroborating_factors": self.corroborating_factors,
            "fail_safe": self.fail_safe,
        }
        d.update(self.settings)
        return d


def select_policy(ctx: NetworkContext) -> Decision:
    """Choose a policy from observed network context.

    Ordered so that every disqualifying condition is checked before any credit is
    given. A BSSID can only ever lose trust here; it can never earn it alone.
    """
    reasons: list[str] = []
    corroborating: list[str] = []

    flags = bssid_flags(ctx.bssid)
    if not flags["valid"]:
        return Decision(
            policy="untrusted",
            trust=UNTRUSTED,
            reasons=["no valid BSSID: cannot associate evidence with a network"],
            fail_safe=True,
        )
    if flags["multicast"]:
        return Decision(
            policy="untrusted",
            trust=UNTRUSTED,
            reasons=["BSSID has the multicast bit set: not a valid AP address"],
            fail_safe=True,
        )

    if ctx.registry_trust == "hostile":
        return Decision(
            policy="hostile",
            trust=HOSTILE,
            reasons=["BSSID recorded as hostile in the registry"],
        )

    # A randomised BSSID means a phone hotspot, a travel router or a spoofed AP.
    if flags["locally_administered"]:
        return Decision(
            policy="untrusted",
            trust=UNTRUSTED,
            reasons=["BSSID is locally administered (randomised): typical of hotspots and spoofed APs"],
            fail_safe=True,
        )

    sec = (ctx.security or "unknown").lower()
    if sec not in EAP_MODES:
        return Decision(
            policy="untrusted",
            trust=UNTRUSTED,
            reasons=[f"security mode {sec!r} provides no server-authenticated network identity"],
            fail_safe=True,
        )

    if ctx.eap_server_validated is not True:
        return Decision(
            policy="untrusted",
            trust=UNTRUSTED,
            reasons=["EAP offered but the server certificate was not validated: evil-twin indistinguishable"],
            fail_safe=True,
        )
    reasons.append("network authenticated the server (EAP with certificate validation)")

    # Independent corroboration. Any single factor is enough to corroborate; none
    # of them is enough to authorise on its own.
    if ctx.gateway_mac and ctx.registry_trust == "managed":
        corroborating.append("gateway MAC consistent with registry")
    if ctx.dhcp_domain and ctx.expected_domain and ctx.dhcp_domain.lower() == ctx.expected_domain.lower():
        corroborating.append("DHCP domain matches registry")
    if ctx.seen_before is True:
        corroborating.append("BSSID previously observed for this estate")

    if ctx.registry_trust != "managed":
        return Decision(
            policy="ambiguous",
            trust=AMBIGUOUS,
            reasons=reasons + ["BSSID not recorded as a managed network; identity unverified"],
            corroborating_factors=corroborating,
        )
    if not corroborating:
        return Decision(
            policy="ambiguous",
            trust=AMBIGUOUS,
            reasons=reasons + ["no independent corroboration of the claimed network identity"],
            corroborating_factors=corroborating,
        )
    if ctx.dhcp_domain and ctx.expected_domain and ctx.dhcp_domain.lower() != ctx.expected_domain.lower():
        return Decision(
            policy="ambiguous",
            trust=AMBIGUOUS,
            reasons=["DHCP domain contradicts the registry entry for this BSSID"],
            corroborating_factors=corroborating,
        )

    return Decision(
        policy="managed",
        trust=MANAGED,
        reasons=reasons,
        corroborating_factors=corroborating,
    )


def envelope_context(ctx: NetworkContext, decision: Decision) -> dict:
    """What gets recorded alongside the evidence.

    A reviewer must be able to see which policy was in force at capture and
    whether it was appropriate. Recording the decision, its reasons and the
    corroborating factors is what makes that checkable later instead of an
    assertion in a report.
    """
    return {
        "schema": "qvault.netpolicy.v1",
        "bssid": normalise_bssid(ctx.bssid),
        "bssid_flags": bssid_flags(ctx.bssid),
        "ssid": ctx.ssid,
        "security": ctx.security,
        "policy": decision.policy,
        "trust": decision.trust,
        "reasons": list(decision.reasons),
        "corroborating_factors": list(decision.corroborating_factors),
        "fail_safe": decision.fail_safe,
        "note": (
            "network context selected the policy; it did not contribute to any key"
        ),
    }

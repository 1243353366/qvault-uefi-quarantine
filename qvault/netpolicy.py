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
import time
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


# --------------------------------------------------------------------------------------
# Policy denial
#
# The policy matrix says what the settings are. It does not say what happens when a caller
# asks for something those settings do not permit, and an operator who receives a bare
# settings dict has no way to tell "not allowed" from "allowed but empty".
#
# A denial here is a record, not a boolean: which rule refused, what it required, what was
# observed, and what would lift it. The observed value is always a count or a label, never
# key material, a credential, or a share - a refusal must not become the leak that the
# oracle tests exist to prevent.
# --------------------------------------------------------------------------------------

DENY_EGRESS = "DENY_EGRESS"
DENY_SEALING = "DENY_UNSEALED_WRITE"
DENY_OVERCOLLECTION = "DENY_OVERCOLLECTION"
DENY_RETENTION = "DENY_OVER_RETENTION"
DENY_CUSTODY = "DENY_INSUFFICIENT_CUSTODY"
DENY_ATTESTATION = "DENY_NO_ATTESTATION"
DENY_UNKNOWN_RESOURCE = "DENY_UNKNOWN_RESOURCE"

#: Resources a caller may request, in the order they are evaluated. Anything absent from
#: this table is refused rather than permitted: an unknown request is not a safe request.
RESOURCES: tuple[str, ...] = (
    "egress", "write", "collection", "retention", "custody", "attestation",
)

_COLLECTION_RANK = {"minimal": 0, "standard": 1, "forensic": 2}


@dataclass
class Denial:
    """One refusal, with enough context for an operator to act on it."""

    resource: str
    code: str
    policy: str
    trust: str
    required: str
    observed: str
    remedy: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "resource": self.resource,
            "code": self.code,
            "policy": self.policy,
            "trust": self.trust,
            "required": self.required,
            "observed": self.observed,
            "remedy": self.remedy,
            **({"detail": self.detail} if self.detail else {}),
        }


@dataclass
class Verdict:
    """The answer to one request. `allowed` is False whenever any denial exists."""

    resource: str
    allowed: bool
    denials: list[Denial] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "resource": self.resource,
            "allowed": self.allowed,
            "denials": [d.to_dict() for d in self.denials],
        }


def _deny(decision: "Decision", resource: str, code: str, required: str,
          observed: str, remedy: str, detail: str = "") -> Denial:
    return Denial(resource=resource, code=code, policy=decision.policy,
                  trust=decision.trust, required=required, observed=observed,
                  remedy=remedy, detail=detail)


def allowance(policy: str) -> dict[str, int]:
    """How much each gate permits under a policy. Higher is more permissive.

    Monotonicity is a property of this table: if every entry for A is at least B's, then
    nothing B allows may be refused by A. Keeping it explicit means the property can be
    tested instead of believed.
    """
    if policy not in POLICIES:
        raise KeyError(f"unknown policy {policy!r}; known: {sorted(POLICIES)}")
    s = POLICIES[policy]
    return {
        "egress": 1 if s["allow_egress"] else 0,
        "retention_days": int(s["retention_days"]),
        "collection": _COLLECTION_RANK[s["collection"]],
        "custody_ease": 5 - int(s["custody"][0]),
        "attestation_waived": 0 if s["require_attestation"] else 1,
        "unsealed_write": 1 - int(bool(s["seal_before_write"])),
    }


def at_least_as_permissive(a: str, b: str) -> bool:
    """Whether policy `a` permits everything `b` permits."""
    la, lb = allowance(a), allowance(b)
    return all(la[k] >= lb[k] for k in la)


def _evaluate(decision: "Decision", resource: str, *, requested=None,
              attested: bool | None = None, shares: int | None = None) -> Verdict:
    """Decide one request under the selected policy.

    `requested` is a collection level or a retention period in days, depending on the
    resource. `shares` is a count of custodians, never the shares themselves.
    """
    settings = decision.settings
    denials: list[Denial] = []

    if resource not in RESOURCES:
        denials.append(_deny(decision, resource, DENY_UNKNOWN_RESOURCE, "a known resource",
                             repr(str(resource))[:32],
                             f"request one of: {', '.join(RESOURCES)}"))
        return Verdict(resource=resource, allowed=False, denials=denials)

    if resource == "egress":
        if not settings["allow_egress"]:
            denials.append(_deny(
                decision, resource, DENY_EGRESS, "allow_egress = true",
                f"allow_egress = false under policy {decision.policy}",
                "move to an authenticated network whose identity is corroborated, or egress "
                "from a host that is not carrying this evidence"))

    elif resource == "write":
        if not settings["seal_before_write"]:
            denials.append(_deny(
                decision, resource, DENY_SEALING, "seal_before_write = true",
                "unsealed writes permitted", "seal the object before it is written"))

    elif resource == "collection":
        want = str(requested if requested is not None else settings["collection"])
        if _COLLECTION_RANK.get(want, 99) > _COLLECTION_RANK.get(settings["collection"], 0):
            denials.append(_deny(
                decision, resource, DENY_OVERCOLLECTION,
                f"collection = {settings['collection']}",
                f"requested {want}",
                "collect only what the policy prescribes here, or re-collect from a "
                "corroborated network where the wider scope is allowed",
                detail="over-collection raises retention and disclosure exposure for evidence "
                       "whose integrity is not yet established"))

    elif resource == "retention":
        want = int(requested if requested is not None else 0)
        if want > int(settings["retention_days"]):
            denials.append(_deny(
                decision, resource, DENY_RETENTION,
                f"retention_days <= {settings['retention_days']}",
                f"requested {want} days",
                "reduce retention, or move the object under a policy that permits it",
                detail="keeping data longer than the policy allows is the failure mode this "
                       "control exists to stop, not a convenience"))

    elif resource == "custody":
        need = int(settings["custody"][0])
        have = need if shares is None else int(shares)
        if have < need:
            denials.append(_deny(
                decision, resource, DENY_CUSTODY, f"{need} of {settings['custody'][1]} custodians",
                f"{have} custodians",
                "enrol more custodians, or retrieve under a policy with a lower threshold",
                detail="a share count is reported; share material is never included"))

    elif resource == "attestation":
        if settings["require_attestation"] and not attested:
            denials.append(_deny(
                decision, resource, DENY_ATTESTATION, "attestation = verified",
                "attested" if attested else "not attested",
                "establish a trust anchor out of band, then re-request",
                detail="a self-report is not an attestation"))

    denials.sort(key=lambda d: (d.code, d.resource))
    return Verdict(resource=resource, allowed=not denials, denials=denials)


# --------------------------------------------------------------------------------------
# Who is allowed to see why
#
# A denial that distinguishes "no such resource" from "that resource is forbidden", or that
# names the rule that refused, is an oracle: it tells an unauthenticated caller which
# resources exist and which conditions are close to passing. So the default answer is
# coarse and identical for every refusal, and detail is only returned to a principal the
# deployment has already authenticated.
# --------------------------------------------------------------------------------------

#: Returned to callers that have not been granted detail. Byte-identical for an unknown
#: resource, a forbidden one, and a policy that simply says no.
#: The only public denial code. A taxonomy with more than one entry would be a partition
#: function: which code came back would say whether the resource existed and which gate
#: was close to passing.
PUBLIC_DENIAL_CODE = "policy_denied"

COARSE_REFUSAL: dict = {
    "allowed": False,
    "code": PUBLIC_DENIAL_CODE,
    "denial": "refused",
    "remedy": "the request was refused by policy; the specific reason is available to the "
              "policy owner",
}


@dataclass(frozen=True)
class Principal:
    """An authenticated caller. `sees_detail` is granted by the deployment, not asserted here.

    Until a deployment wires this to its own authentication, treat every Principal as
    unverified: the coarse path is the only one that is safe without an authn layer.
    """

    name: str = ""
    role: str = ""
    sees_detail: bool = False

    @property
    def may_see_detail(self) -> bool:
        return bool(self.sees_detail and self.role and self.name)


def denial_record(decision: "Decision", resource: str, *, principal: Principal | None = None,
                  requested=None, attested: bool | None = None,
                  shares: int | None = None) -> dict:
    """The reason, for the policy owner's log. Never returned to the caller."""
    verdict = _evaluate(decision, resource, requested=requested, attested=attested,
                        shares=shares)
    return {"resource": resource, "allowed": verdict.allowed, "policy": decision.policy,
            "trust": decision.trust, "codes": [d.code for d in verdict.denials],
            "caller": (principal.name if principal else ""), "at": int(time.time())}


def authorize(decision: "Decision", resource: str, *, principal: Principal | None = None,
              requested=None, attested: bool | None = None,
              shares: int | None = None, audit=None) -> dict:
    """Answer one request, saying as little as the caller has earned.

    The evaluation always runs, so a refusal costs the same work whichever rule produced
    it; only the report differs.
    """
    detailed = principal is not None and principal.may_see_detail
    try:
        verdict = _evaluate(decision, resource, requested=requested, attested=attested,
                            shares=shares)
    except Exception as exc:                     # noqa: BLE001 - a rule error is a denial
        # Fail closed: an evaluator that cannot answer must not answer "allowed".
        record = {"resource": resource, "allowed": False, "policy": decision.policy,
                  "trust": decision.trust, "codes": ["EVALUATION_ERROR"],
                  "error": type(exc).__name__, "at": int(time.time())}
        if audit is not None:
            audit(record)
        if not detailed:
            return dict(COARSE_REFUSAL)
        return {"allowed": False, "resource": resource,
                "denials": [{"resource": resource, "code": "DENY_EVALUATION_ERROR",
                             "policy": decision.policy, "trust": decision.trust,
                             "required": "an evaluable request",
                             "observed": type(exc).__name__,
                             "remedy": "fix the request or the policy; nothing was allowed "
                                       "while the evaluator was failing"}]}

    if not detailed:
        if verdict.allowed:
            return {"allowed": True}
        if audit is not None:
            audit({"resource": resource, "allowed": False, "policy": decision.policy,
                   "trust": decision.trust,
                   "codes": [d.code for d in verdict.denials],
                   "caller": (principal.name if principal else ""),
                   "at": int(time.time())})
        return dict(COARSE_REFUSAL)
    return {"allowed": verdict.allowed, "resource": resource,
            "denials": [d.to_dict() for d in verdict.denials]}


def authorize_all(decision: "Decision", requests: dict[str, dict], *,
                  principal: Principal | None = None) -> dict:
    """Evaluate several requests at once. Deterministic order, so reports diff cleanly."""
    verdicts = {}
    for resource in sorted(requests):
        kwargs = dict(requests[resource] or {})
        verdicts[resource] = authorize(decision, resource, principal=principal, **kwargs)
    detailed = principal is not None and principal.may_see_detail
    out = {"allowed": all(v["allowed"] for v in verdicts.values())}
    if detailed:
        out["policy"] = decision.policy
        out["trust"] = decision.trust
        out["verdicts"] = verdicts
    else:
        # No resource names, no count of which failed, no policy identity.
        out["denial" if not out["allowed"] else "verdicts"] = (
            "refused" if not out["allowed"] else len(verdicts))
    return out

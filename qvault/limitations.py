"""
qvault.limitations
==================

Four architectural limitations, modelled instead of merely admitted.

The limitations
---------------
1. **Limited live-state visibility.** Historical records can miss an active
   compromise. Control: optional live-response acquisition.
2. **Firmware blind spots.** OS-level scans cannot establish firmware integrity.
   Control: independent firmware acquisition.
3. **Baseline limitations.** Legitimate unusual behaviour looks suspicious.
   Control: per-device behavioural baselines.
4. **Indicator trust.** Bad or poisoned intelligence produces bad findings.
   Control: source provenance and independent validation.

Why a model rather than a caveat list
-------------------------------------
Each of those controls buys something specific and cannot buy something else, and
the difference is not rhetorical. So the module treats every source of evidence as
a *plane* with properties that determine what a claim may rest on:

* `forgeable_by_subject` — can the thing under suspicion influence this evidence?
* `attacker_influence` — none / low / high.
* `requires_physical` — does it need hands on hardware?

A claim's strength is then computed, not asserted: a proposition is supported only
by planes that actually establish it, and against a capable adversary only by
planes the subject cannot forge.

Two traps this catches
----------------------
**"Independent" firmware acquisition usually isn't.** Reading flash through a
kernel driver is `firmware_via_os`: the implant can answer the read. Only an
out-of-band read is independent, and that needs physical access whose read-back
equivalence is itself unverified (see HARDWARE_TEST_QUESTIONS.md H8).

**A baseline captured after compromise certifies the attacker as normal.** If the
implant was resident when the baseline was learned, its behaviour *is* the baseline
and every subsequent deviation is measured from a poisoned origin. Baseline
validity is therefore a property to be established, never assumed.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- propositions we might want to claim ----------------------------------

P_PROCESS_EXISTED = "process_existed"
P_FILE_CONTENT = "file_content"
P_NETWORK_CONTACT = "network_contact"
P_HISTORICAL_ACTIVITY = "historical_activity"
P_FIRMWARE_INTEGRITY = "firmware_integrity"
P_BEHAVIOUR_NORMAL = "behaviour_is_normal"
P_OBJECT_MALICIOUS = "object_is_malicious"

PROPOSITIONS = (
    P_PROCESS_EXISTED, P_FILE_CONTENT, P_NETWORK_CONTACT, P_HISTORICAL_ACTIVITY,
    P_FIRMWARE_INTEGRITY, P_BEHAVIOUR_NORMAL, P_OBJECT_MALICIOUS,
)

# --- evidence planes ------------------------------------------------------

LIVE_STATE = "live_state"
HISTORICAL = "historical_record"
WIRE = "wire"
FIRMWARE_VIA_OS = "firmware_via_os"
FIRMWARE_OOB = "firmware_out_of_band"
INTEL = "threat_intel"
BASELINE = "baseline"

CONF_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
_INFLUENCE_CONF = {"none": "high", "low": "medium", "high": "low"}


@dataclass(frozen=True)
class PlaneProfile:
    plane: str
    establishes: frozenset[str]
    attacker_influence: str  # none | low | high
    forgeable_by_subject: bool
    requires_physical: bool
    note: str


PROFILES: dict[str, PlaneProfile] = {
    LIVE_STATE: PlaneProfile(
        LIVE_STATE,
        frozenset({P_PROCESS_EXISTED, P_FILE_CONTENT}),
        "high", True, False,
        "read through the subject's own kernel, which the implant may be inside",
    ),
    HISTORICAL: PlaneProfile(
        HISTORICAL,
        frozenset({P_HISTORICAL_ACTIVITY, P_FILE_CONTENT, P_NETWORK_CONTACT}),
        "high", True, False,
        "written by the subject; cannot show what was never recorded, and an implant "
        "resident throughout may simply have not been logged",
    ),
    WIRE: PlaneProfile(
        WIRE,
        frozenset({P_NETWORK_CONTACT}),
        "none", False, False,
        "the endpoint cannot forge packets that never left the machine",
    ),
    FIRMWARE_VIA_OS: PlaneProfile(
        FIRMWARE_VIA_OS,
        frozenset({P_FIRMWARE_INTEGRITY}),
        "high", True, False,
        "an implant answering the read reports whatever it wants; this is the "
        "OS-level scan that cannot establish firmware integrity",
    ),
    FIRMWARE_OOB: PlaneProfile(
        FIRMWARE_OOB,
        frozenset({P_FIRMWARE_INTEGRITY}),
        "none", False, True,
        "out-of-band read is independent of the subject, but in-circuit read-back "
        "equivalence is unverified (H8)",
    ),
    INTEL: PlaneProfile(
        INTEL,
        frozenset({P_OBJECT_MALICIOUS}),
        "high", True, False,
        "asserted by a third party; a poisoned feed can whitelist an adversary's own "
        "indicator, which produces false negatives more cheaply than false positives",
    ),
    BASELINE: PlaneProfile(
        BASELINE,
        frozenset({P_BEHAVIOUR_NORMAL}),
        "high", True, False,
        "learned from observation, so it inherits whatever was resident at the time",
    ),
}

PLANES = tuple(PROFILES)


def _confidence(plane: str) -> str:
    return _INFLUENCE_CONF[PROFILES[plane].attacker_influence]


def establish(proposition: str, planes, *, adversarial: bool = False) -> dict:
    """What can this set of evidence planes establish about a proposition?

    `adversarial=True` counts only planes the subject cannot forge, which is the
    honest setting when the subject is capable of deliberate deception.
    """
    if proposition not in PROPOSITIONS:
        raise ValueError(f"unknown proposition {proposition!r}")
    planes = list(dict.fromkeys(planes))
    for p in planes:
        if p not in PROFILES:
            raise ValueError(f"unknown plane {p!r}")

    supporting = [p for p in planes if proposition in PROFILES[p].establishes]
    would_need = [p for p in PLANES if proposition in PROFILES[p].establishes]

    if not supporting:
        return {
            "proposition": proposition,
            "status": "unsupported",
            "supporting_planes": [],
            "would_need": would_need,
            "confidence": "none",
            "adversarial_confidence": "none",
            "caveats": [
                f"no supplied plane can establish {proposition}; "
                f"it requires one of: {', '.join(would_need)}"
            ],
        }

    best = max(supporting, key=lambda p: CONF_RANK[_confidence(p)])
    confidence = _confidence(best)

    ungovernable = [p for p in supporting if not PROFILES[p].forgeable_by_subject]
    if ungovernable:
        adv_best = max(ungovernable, key=lambda p: CONF_RANK[_confidence(p)])
        adversarial_confidence = _confidence(adv_best)
    else:
        adversarial_confidence = "none"

    caveats = [f"{p}: {PROFILES[p].note}" for p in supporting]
    if adversarial and adversarial_confidence == "none":
        caveats.append(
            "every supporting plane is forgeable by the subject: this cannot be "
            "stated against an adversary, only about a cooperative system"
        )

    return {
        "proposition": proposition,
        "status": "supported",
        "supporting_planes": supporting,
        "would_need": would_need,
        "confidence": confidence,
        "adversarial_confidence": adversarial_confidence,
        "best_plane": best,
        "caveats": caveats,
    }


# --- limitation 3: baseline validity --------------------------------------


def baseline_validity(
    captured_at: float,
    compromise_window_start: float | None = None,
) -> dict:
    """Is a behavioural baseline trustworthy as a definition of normal?

    Absence of evidence of earlier compromise is not evidence the baseline is
    clean, so an unknown compromise time yields `unverified`, never `valid`.
    """
    if compromise_window_start is None:
        return {
            "status": "unverified",
            "reason": (
                "compromise window unknown: the baseline may have been learned with the "
                "implant already resident, in which case the implant defined normal"
            ),
            "action": "re-baseline from a known-good rebuild, or treat deviations as "
                      "uncalibrated rather than anomalous",
        }
    if captured_at >= compromise_window_start:
        return {
            "status": "poisoned",
            "reason": "baseline captured at or after the earliest suspected compromise",
            "action": "discard the baseline; it certifies attacker behaviour as normal",
        }
    return {
        "status": "valid",
        "reason": "baseline predates the earliest suspected compromise",
        "action": "usable, subject to drift limits; re-validate after any rebuild",
    }


# --- limitation 4: indicator trust ----------------------------------------

STALE_DAYS = 365.0


@dataclass(frozen=True)
class IntelFeed:
    name: str
    upstream: str      # who actually produced the indicator
    age_days: float
    has_provenance: bool = True
    validated_independently: bool = False


def intel_trust(feeds) -> dict:
    """Assess whether indicator sources can support a maliciousness claim.

    Resold intelligence is not independent intelligence. Three feeds quoting one
    upstream is one source, and treating it as three is how a single poisoned
    indicator becomes a consensus.
    """
    feeds = list(feeds)
    if not feeds:
        return {"standing": "none", "independent_sources": 0,
                "caveats": ["no indicators supplied"], "supports_malicious_claim": False}

    upstreams = {f.upstream for f in feeds if f.has_provenance}
    independent = {f.upstream for f in feeds if f.has_provenance and f.validated_independently}
    caveats: list[str] = []

    if len(feeds) > 1 and len(upstreams) == 1:
        standing = "circular"
        caveats.append(
            f"{len(feeds)} feeds resolve to one upstream ({next(iter(upstreams))}): "
            "agreement here is repetition, not corroboration"
        )
    elif len(independent) >= 2:
        standing = "corroborated"
    elif len(upstreams) >= 2:
        standing = "uncorroborated"
        caveats.append(
            f"{len(upstreams)} distinct upstreams agree, but none is independently "
            "validated: agreement between resellers is weak evidence, not corroboration"
        )
    elif len(upstreams) == 1:
        standing = "single_source"
        caveats.append("one upstream: a single poisoned source is indistinguishable from truth")
    else:
        standing = "unverifiable"
        caveats.append("no feed carries provenance")

    stale = [f.name for f in feeds if f.age_days > STALE_DAYS]
    if stale:
        caveats.append(f"stale beyond {STALE_DAYS:.0f} days: {', '.join(sorted(stale))}")
    if any(not f.has_provenance for f in feeds):
        caveats.append("at least one feed carries no provenance and cannot be validated")

    return {
        "standing": standing,
        "feeds": len(feeds),
        "distinct_upstreams": len(upstreams),
        "independent_validated": len(independent),
        "stale": stale,
        "caveats": caveats,
        "supports_malicious_claim": standing == "corroborated",
    }


# --- the registry the report is generated from ----------------------------

LIMITATIONS = [
    {
        "id": "A1",
        "limitation": "limited live-state visibility",
        "consequence": "historical records can miss an active compromise",
        "control": "optional live-response acquisition",
        "buys": "current process, connection and memory state that logging never captured",
        "cannot_buy": "integrity; live state is read through the subject's kernel, so an "
                      "implant inside that kernel answers the questions",
        "residual": "live acquisition also mutates the subject (timestamps, memory, "
                    "network connections), so it degrades the very history it supplements",
    },
    {
        "id": "A2",
        "limitation": "firmware blind spots",
        "consequence": "OS-level scans cannot establish firmware integrity",
        "control": "independent firmware acquisition",
        "buys": "the only evidence that does not route through the subject",
        "cannot_buy": "coverage without physical access, or proof that in-circuit read-back "
                      "equals the chip's contents (H8)",
        "residual": "an implant that answers SPI reads through a compromised SMM is "
                    "indistinguishable from a clean image when read through the OS; only "
                    "out-of-band acquisition escapes that, and it needs hands on hardware",
    },
    {
        "id": "A3",
        "limitation": "baseline limitations",
        "consequence": "legitimate unusual behaviour can look suspicious",
        "control": "per-device behavioural baselines",
        "buys": "fewer false positives from genuinely unusual but legitimate work",
        "cannot_buy": "validity when the baseline was learned after compromise, or "
                      "protection against slow drift that trains the baseline",
        "residual": "an implant resident for the whole learning window becomes the "
                    "definition of normal; long-dwell adversaries are favoured by "
                    "baselines rather than disadvantaged",
    },
    {
        "id": "A4",
        "limitation": "indicator trust",
        "consequence": "bad or poisoned intelligence can generate bad findings",
        "control": "source provenance and independent validation",
        "buys": "resistance to a single feed's error, and a visible chain of custody for "
                "each indicator",
        "cannot_buy": "independence when feeds resell one upstream, or protection against "
                      "an adversary who poisons the upstream itself",
        "residual": "poisoning most cheaply produces false negatives, by whitelisting the "
                    "adversary's own indicator; a suppression attack is quieter than a "
                    "false-alarm attack and is what a capable actor would choose",
    },
]


def audit_claim(proposition: str, planes, *, adversarial: bool = True) -> dict:
    """Convenience wrapper: is this claim defensible, and against whom?"""
    result = establish(proposition, planes, adversarial=adversarial)
    result["defensible"] = result["adversarial_confidence"] != "none"
    return result

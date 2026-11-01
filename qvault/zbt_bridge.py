"""
qvault.zbt_bridge
=================

The seam between upstream detection logic and local grading discipline.

What each side owns
-------------------
Upstream (`vendor/zbtriage`) owns **detection**: which artifacts to read, which
indicator matched, and which artifact class made it match. That is real work and it is
kept unmodified.

This module owns **grading**: what such a match is worth as evidence, how it is
downgraded when the collection had gaps, and whether it may carry an attribution. The
two vocabularies are not the same shape, and pretending otherwise is how a
well-built detector's output gets overstated by whoever consumes it.

Their grade describes the *artifact*: `on-disk` means a file fingerprint matched.
My grade describes the *evidence*: how strongly it supports a claim against an
adversary who can lie. A fingerprint read through the subject's operating system is
corroborated that the bytes are present, and worth nothing against an implant that
can hide them.

The anti-drift guard
--------------------
`EVIDENCE_MAP` must cover `zbt.EVIDENCE_ORDER` exactly. If upstream adds or renames a
grade, this module's coverage test fails rather than quietly treating the new artifact
class as benign. That is the whole reason for vendoring a pinned snapshot instead of
forking: upstream stays authoritative, and the seam stays testable.
"""

from __future__ import annotations

from vendor.zbtriage import result as zbt

from . import findings as F
from . import limitations as L

# Upstream's mandatory closing line, quoted verbatim from its doctrine (D1). Kept
# word-for-word because it is the sentence that stops "nothing found" becoming
# "you are fine".
D1_LINE = (
    "No known indicators were found in the places that can be checked. "
    "This is not a clean bill of health."
)

# Their artifact class -> (evidence plane, my grade, why the two differ)
EVIDENCE_MAP: dict[str, dict] = {
    zbt.EV_ON_DISK: {
        "plane": L.HISTORICAL, "grade": F.CORROBORATED,
        "why": "a published sample's fingerprint matched a file: conclusive that the "
               "bytes are there, and still a read made through the subject",
    },
    zbt.EV_ON_DEVICE: {
        "plane": L.HISTORICAL, "grade": F.CORROBORATED,
        "why": "the named object is present on the device, as reported by the device",
    },
    zbt.EV_FILE_PATTERN: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "a research rule matched; the rule needs verification before the match "
               "means anything",
    },
    zbt.EV_PERSISTENCE: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "named in an auto-start registration: registration is not execution",
    },
    zbt.EV_COMMAND: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "named in a command that ran here; the runner is inferred from logs",
    },
    zbt.EV_EXECUTION: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "an execution record names the binary; records can be pruned",
    },
    zbt.EV_INVENTORY: {
        "plane": L.HISTORICAL, "grade": F.HYPOTHESIS,
        "why": "inventory identity only: presence unverified, execution unknown",
    },
    zbt.EV_CONTACTED: {
        "plane": L.HISTORICAL, "grade": F.CORROBORATED,
        "why": "the device demonstrably talked to the host, per the device's own logs; "
               "becomes wire-grade only with an independent capture",
    },
    zbt.EV_RECEIVED: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "appeared in a message that arrived; reading is not opening",
    },
    zbt.EV_DEVICE_LOG: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "named in the phone's own system logs, which the phone writes",
    },
    zbt.EV_DNS: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "a resolver record; endpoint contact unverified",
    },
    zbt.EV_ATTEMPTED: {
        "plane": L.HISTORICAL, "grade": F.HYPOTHESIS,
        "why": "a lookup happened and a filter blocked it: intent inferred, contact did not occur",
    },
    zbt.EV_CONFIGURED: {
        "plane": L.HISTORICAL, "grade": F.INFERRED,
        "why": "named in local config, not as a block",
    },
    zbt.EV_REFERENCED: {
        "plane": L.HISTORICAL, "grade": F.HYPOTHESIS,
        "why": "the string appeared in saved content: reading about a campaign is not "
               "contact with it, which is why upstream treats this grade as benign",
    },
}

#: Retained so a caller can be explicit that IOC triage is not wire evidence.
IOC_PLANE = L.HISTORICAL


class BridgeError(ValueError):
    """Raised when upstream vocabulary and local grading have diverged."""


def assert_vocabulary() -> None:
    """Fail loudly if upstream adds or renames an evidence grade."""
    upstream = set(zbt.EVIDENCE_ORDER)
    mapped = set(EVIDENCE_MAP)
    if upstream != mapped:
        raise BridgeError(
            "evidence vocabulary drift: unmapped upstream grades "
            f"{sorted(upstream - mapped)}, stale local grades {sorted(mapped - upstream)}. "
            "Map the new grade deliberately rather than letting it default to benign."
        )


def mapping_for(evidence: str) -> dict:
    """Plane and grade for an artifact class, treating unknown grades as serious.

    Upstream's rule is a deny-list: only `referenced` is benign, so a missing or
    misspelled grade is serious. That intent is preserved, but seriousness is not
    inflated into confidence: an unrecognised class is graded HYPOTHESIS with an
    explicit gap, not promoted to corroborated.
    """
    if evidence in EVIDENCE_MAP:
        return dict(EVIDENCE_MAP[evidence], known=True)
    return {
        "plane": IOC_PLANE,
        "grade": F.HYPOTHESIS,
        "why": f"unrecognised evidence class {evidence!r}: treated as serious per "
               "upstream doctrine, and graded as a hypothesis because this module does "
               "not know what the artifact can establish",
        "known": False,
    }


def is_serious(evidence: str) -> bool:
    """Delegate to upstream: its deny-list is the authority on benign classes."""
    return zbt.is_serious(evidence)


def module_gaps(module_result) -> tuple[str, ...]:
    """Blind spots for one module: checks that did not run, plus its status."""
    gaps = [f"check_not_run:{c.name}" for c in module_result.checks if not c.ran]
    if module_result.status in (zbt.UNKNOWN, zbt.PARTIAL) and not gaps:
        gaps.append(f"module_status:{module_result.status}")
    if module_result.skipped:
        gaps.append(f"records_skipped:{module_result.skipped}")
    return tuple(gaps)


def observations(module_result) -> list[F.Observation]:
    """Every hit, as a graded observation. Never as a finding.

    A finding requires a benign alternative and a human adjudication (rules F1/F2),
    which a detector cannot supply on its own behalf.
    """
    gaps = module_gaps(module_result)
    out = []
    for hit in module_result.hits:
        m = mapping_for(hit.evidence)
        extra = () if m["known"] else ("unknown_evidence_class",)
        statement = (
            f"{hit.indicator} matched at {hit.location}"
            + (f" ({hit.detail})" if hit.detail else "")
            + (f"; family suggested: {hit.family}" if hit.family else "")
        )
        out.append(
            F.Observation(
                statement=statement,
                plane=m["plane"],
                grade=m["grade"],
                telemetry_gaps=tuple(gaps) + extra,
                source=hit.source or module_result.name,
            )
        )
    return out


def run_verdict(module_results) -> dict:
    """Aggregate module results without ever asserting a clean device.

    Mapped to this project's vocabulary, which has no `clean` value to return:
    hits -> suspicious (IOC triage alone never reaches malicious_indicated),
    gaps -> inconclusive, neither -> no_evidence_found.
    """
    results = list(module_results)
    serious_hits = [
        h for r in results for h in r.hits if is_serious(h.evidence)
    ]
    gaps = tuple(g for r in results for g in module_gaps(r))

    if serious_hits:
        verdict = F.SUSPICIOUS_VERDICT
    elif gaps:
        verdict = F.INCONCLUSIVE
    else:
        verdict = F.NO_EVIDENCE_FOUND

    if verdict not in (F.NO_EVIDENCE_FOUND, F.INCONCLUSIVE, F.SUSPICIOUS_VERDICT,
                       F.MALICIOUS_VERDICT):
        raise BridgeError(f"verdict {verdict!r} is outside the permitted vocabulary")
    if verdict in F.FORBIDDEN_VERDICTS:
        raise BridgeError("a cleanliness verdict was produced; this is a bug")

    head = (
        f"{len(serious_hits)} indicator match(es) across {len(results)} module(s)."
        if serious_hits else D1_LINE
    )
    return {
        "verdict": verdict,
        "serious_hits": len(serious_hits),
        "gaps": list(gaps),
        "unobserved_checks": sorted({g.split(":", 1)[1] for g in gaps
                                     if g.startswith("check_not_run:")}),
        "statement": head + (f" Gaps remain: {len(gaps)}." if gaps else ""),
        "adversarial_value": "none" if not serious_hits else
                             "limited: IOC triage is historical-plane evidence",
    }


def promote(observation: F.Observation, benign_explanations, attribution=None) -> F.Finding:
    """Turn an observation into a finding by supplying what a detector cannot.

    Deliberately awkward: the caller must name a plausible benign explanation and the
    status is then derived by rule F2, not chosen.
    """
    return F.Finding(
        identifier=f"zbt:{abs(hash(observation.statement)) % 10**8:08d}",
        observation=observation,
        benign_explanations=tuple(benign_explanations),
        attribution=attribution,
    )


def attribution_refusal(hit, feeds) -> dict | None:
    """Whether indicator provenance permits naming a family.

    A single feed cannot support attribution however confident its label looks:
    see A4, where poisoning to cause a false negative is the quiet attack.
    """
    trust = L.intel_trust(feeds)
    if trust["supports_malicious_claim"]:
        return None
    return {
        "refused": True,
        "indicator": hit.indicator,
        "suggested_family": hit.family,
        "standing": trust["standing"],
        "why": "family attribution requires two independently validated upstreams",
        "caveats": trust["caveats"],
    }


def adversarial_value(evidence: str) -> dict:
    """What this grade is worth when the subject is trying to deceive you."""
    m = mapping_for(evidence)
    result = L.establish(L.P_HISTORICAL_ACTIVITY, [m["plane"]], adversarial=True)
    return {
        "evidence": evidence,
        "plane": m["plane"],
        "grade": m["grade"],
        "adversarial_confidence": result["adversarial_confidence"],
        "why": m["why"],
    }

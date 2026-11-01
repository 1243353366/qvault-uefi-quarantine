"""
qvault.netobs
=============

Network observation with an explicit honesty model about attribution.

Records DNS, flow metadata, process ancestry and destination classification for a
suspect host, then does the one thing that is actually hard: joins what the host
*claims* against what the wire *shows*, and reports the disagreements.

Why the join matters
--------------------
On a clean host, "which process owns this socket" is a fact reported by the
kernel. On a host compromised by any of the families in this project it is a
claim, because the implant has deliberately arranged for legitimate components to
own the traffic: BlackLotus injects into `winlogon.exe`, MoonBounce into a
`SVCHOST.EXE -K NETSVCS` instance. Endpoint accounting then names a signed
Microsoft binary and is telling the truth about everything except the thing you
care about.

So each flow carries an attribution tier (`wire_only`, `claimed_only`,
`corroborated`, `conflict`) and the analyst's attention is pointed at the delta.
A `corroborated` tier means two sources agree. It does not mean the attribution
is true: an implant that hooks both the socket layer and the accounting that
the kernel exposes lies consistently to both.

Design notes and failure modes: report/NETOBS_MODULE.md.
Privacy constraints there are requirements: metadata only, no payloads, no query
strings, no third-party traffic.
"""

from __future__ import annotations

import ipaddress
import json
import statistics
from dataclasses import asdict, dataclass, field
from typing import Iterable, Sequence

# Network kinds computed from the address itself. No feed, no error.
CGNAT = ipaddress.ip_network("100.64.0.0/10")
DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]
SIX_TO_FOUR = ipaddress.ip_network("2002::/16")

# Attribution tiers, in ascending order of trustworthiness.
WIRE_ONLY = "wire_only"
CLAIMED_ONLY = "claimed_only"
CORROBORATED = "corroborated"
CONFLICT = "conflict"

DEFAULT_TOLERANCE_S = 2.0


@dataclass(frozen=True)
class DnsEvent:
    ts: float
    host: str
    qname: str
    qtype: str = "A"
    rcode: str = "NOERROR"
    answers: tuple[str, ...] = ()
    resolver: str | None = None
    pid: int | None = None
    image: str | None = None
    source: str = "host"  # "host" | "resolver"
    tier: str = CLAIMED_ONLY


@dataclass(frozen=True)
class FlowEvent:
    ts: float
    host: str
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    src_port: int = 0
    ts_end: float | None = None
    bytes_out: int = 0
    bytes_in: int = 0
    # Everything below is the host's claim unless source == "wire".
    pid: int | None = None
    image: str | None = None
    cmdline: str | None = None
    parent_chain: tuple[str, ...] = ()
    user: str | None = None
    uri: str | None = None
    source: str = "host"
    tier: str = CLAIMED_ONLY


@dataclass(frozen=True)
class ProcessNode:
    pid: int
    image: str
    ppid: int | None = None
    user: str | None = None
    session: int | None = None
    image_sha256: str | None = None


@dataclass
class Finding:
    kind: str
    severity: str
    summary: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity,
                "summary": self.summary, "evidence": self.evidence}


# ---------------------------------------------------------------------------
# Destination classification — three separate claims, never one score
# ---------------------------------------------------------------------------


def classify_destination(
    ip: str,
    *,
    organization: str | None = None,
    category: str | None = None,
    feed: str | None = None,
    feed_age_days: float | None = None,
    first_seen_for_host: bool | None = None,
) -> dict:
    """Classify a destination address.

    Scope (internal/special/external) is arithmetic and therefore deterministic.
    Organisation and category are feed assertions and are labelled as such, with
    the feed and its age. They are deliberately *not* merged into a reputation
    score: a deterministic fact wearing a reputation label is how analysts end up
    arguing about arithmetic.
    """
    out = {
        "ip": ip,
        "scope": "unknown",
        "reason": "",
        "scope_confidence": "deterministic",
        "organization": organization,
        "category": category,
        "feed": feed,
        "feed_age_days": feed_age_days,
        "label_confidence": "feed" if (organization or category) else "none",
        "first_seen_for_host": first_seen_for_host,
    }
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        out["reason"] = "not an IP address"
        return out

    def mark(scope: str, reason: str) -> dict:
        out["scope"] = scope
        out["reason"] = reason
        return out

    if addr.is_unspecified:
        return mark("special", "unspecified address")
    if addr.is_loopback:
        return mark("internal", "loopback")
    if addr.is_multicast:
        return mark("special", "multicast")
    if addr.is_link_local:
        return mark("internal", "link-local")
    if any(addr in net for net in DOC_NETS):
        return mark("special", "documentation range")
    if isinstance(addr, ipaddress.IPv4Address) and addr in CGNAT:
        return mark("special", "carrier-grade NAT: attribution is shared across subscribers")
    if addr.is_private:
        return mark("internal", "private address space")
    if isinstance(addr, ipaddress.IPv6Address) and addr in SIX_TO_FOUR:
        return mark("special", "6to4 tunnel address")
    if addr.is_reserved:
        return mark("special", "reserved")
    return mark("external", "globally routable")


# ---------------------------------------------------------------------------
# Attribution correlation
# ---------------------------------------------------------------------------


def _flow_key(f: FlowEvent) -> tuple:
    return (f.dst_ip, f.dst_port, f.proto.lower())


def correlate(
    host_flows: Sequence[FlowEvent],
    wire_flows: Sequence[FlowEvent],
    *,
    tolerance_s: float = DEFAULT_TOLERANCE_S,
    volume_tolerance: float = 0.5,
) -> list[Finding]:
    """Join host-claimed flows against wire-observed flows.

    Emits findings only for disagreements. Agreement is not reported, because a
    thousand corroborated rows do not need an analyst and would bury the four
    rows that do.
    """
    findings: list[Finding] = []
    used: set[int] = set()

    for h in host_flows:
        match = None
        for i, w in enumerate(wire_flows):
            if i in used or _flow_key(h) != _flow_key(w):
                continue
            if abs(h.ts - w.ts) > tolerance_s:
                continue
            match = i
            break

        if match is None:
            findings.append(
                Finding(
                    kind="phantom_claim",
                    severity="high",
                    summary=(
                        "host reports a flow the wire never saw "
                        f"({h.dst_ip}:{h.dst_port}/{h.proto})"
                    ),
                    evidence={
                        "host": h.host,
                        "claimed_image": h.image,
                        "claimed_pid": h.pid,
                        "ts": h.ts,
                        "note": "accounting may be fabricated, spoofed, or the traffic never left the machine",
                    },
                )
            )
            continue

        used.add(match)
        w = wire_flows[match]

        # Differing image for the same 5-tuple inside the window.
        if h.image and w.image and h.image.lower() != w.image.lower():
            findings.append(
                Finding(
                    kind="attribution_conflict",
                    severity="high",
                    summary="host and wire disagree on which image owns the flow",
                    evidence={
                        "host": h.host,
                        "dst": f"{h.dst_ip}:{h.dst_port}",
                        "host_image": h.image,
                        "wire_image": w.image,
                    },
                )
            )
            continue

        # Host claims egress the wire never carried.
        if h.bytes_out > 0 and w.bytes_out == 0:
            findings.append(
                Finding(
                    kind="attribution_conflict",
                    severity="high",
                    summary="host claims egress bytes that the wire did not carry",
                    evidence={
                        "host": h.host,
                        "dst": f"{h.dst_ip}:{h.dst_port}",
                        "host_bytes_out": h.bytes_out,
                        "wire_bytes_out": w.bytes_out,
                    },
                )
            )
            continue

        # Volume disagreement beyond tolerance is a softer signal: sampling and
        # retransmission can explain a lot, so this is medium, not high.
        if w.bytes_out > 0 and abs(h.bytes_out - w.bytes_out) > volume_tolerance * max(
            h.bytes_out, w.bytes_out
        ):
            findings.append(
                Finding(
                    kind="volume_mismatch",
                    severity="medium",
                    summary="host and wire disagree substantially on egress volume",
                    evidence={
                        "host": h.host,
                        "dst": f"{h.dst_ip}:{h.dst_port}",
                        "host_bytes_out": h.bytes_out,
                        "wire_bytes_out": w.bytes_out,
                    },
                )
            )

    for i, w in enumerate(wire_flows):
        if i in used:
            continue
        findings.append(
            Finding(
                kind="unattributed_egress",
                severity="high",
                summary=(
                    "wire observed a flow no host process claims "
                    f"({w.dst_ip}:{w.dst_port}/{w.proto})"
                ),
                evidence={
                    "host": w.host,
                    "bytes_out": w.bytes_out,
                    "ts": w.ts,
                    "note": "host accounting is blind, incomplete, or suppressed",
                },
            )
        )

    return findings


def tier_for(host_flow: FlowEvent, findings: Iterable[Finding]) -> str:
    """Assign an attribution tier to one host flow, given the correlation result."""
    dst = f"{host_flow.dst_ip}:{host_flow.dst_port}"
    for f in findings:
        if f.evidence.get("dst") == dst and f.severity == "high":
            return CONFLICT
    return CORROBORATED


# ---------------------------------------------------------------------------
# Beaconing
# ---------------------------------------------------------------------------


def beacon_score(timestamps: Sequence[float], *, min_intervals: int = 4) -> dict:
    """Score the regularity of contact intervals.

    A high score is a lead, never a conclusion: cron, NTP, updaters and health
    checks are all periodic. A low score means nothing, because jitter defeats
    this trivially.
    """
    times = sorted(float(t) for t in timestamps)
    intervals = [b - a for a, b in zip(times, times[1:])]
    if len(intervals) < min_intervals:
        return {
            "n_intervals": len(intervals),
            "score": None,
            "verdict": "insufficient_data",
            "reason": f"need at least {min_intervals} intervals",
        }
    median = statistics.median(intervals)
    if median <= 0:
        return {"n_intervals": len(intervals), "score": None,
                "verdict": "invalid", "reason": "non-positive median interval"}
    regular = sum(1 for i in intervals if abs(i - median) <= 0.2 * median) / len(intervals)
    mean = statistics.fmean(intervals)
    cv = (statistics.pstdev(intervals) / mean) if mean else 0.0
    score = regular * max(0.0, 1.0 - cv / 0.5)
    if score >= 0.7:
        verdict = "regular"
    elif score >= 0.4:
        verdict = "weakly_regular"
    else:
        verdict = "irregular"
    return {
        "n_intervals": len(intervals),
        "median_interval_s": round(median, 3),
        "regular_fraction": round(regular, 3),
        "cv": round(cv, 3),
        "score": round(score, 3),
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# Rules derived from documented family behaviour
# ---------------------------------------------------------------------------

EXTERNAL_ONLY_NOTES = "endpoint accounting is a claim, not a fact; see NETOBS_MODULE.md §2"


def evaluate_rules(
    flows: Iterable[FlowEvent],
    dns: Iterable[DnsEvent] = (),
) -> list[Finding]:
    """Apply the family-shape rules from NETOBS_MODULE.md §7."""
    out: list[Finding] = []
    for f in flows:
        image = (f.image or "").lower().replace("\\", "/").rsplit("/", 1)[-1]
        dest = classify_destination(f.dst_ip)
        external = dest["scope"] == "external"

        if image == "winlogon.exe" and external:
            out.append(
                Finding(
                    kind="blacklotus_winlogon_egress",
                    severity="high",
                    summary="winlogon.exe originating external traffic",
                    evidence={"dst": f"{f.dst_ip}:{f.dst_port}", "uri": f.uri,
                              "basis": "BlackLotus injects a downloader into winlogon.exe",
                              "caution": EXTERNAL_ONLY_NOTES},
                )
            )
        if f.uri and "/api/hpb_gate.php" in f.uri.lower():
            out.append(
                Finding(
                    kind="blacklotus_gate_path",
                    severity="high",
                    summary="documented BlackLotus C2 path observed",
                    evidence={"dst": f"{f.dst_ip}:{f.dst_port}", "uri": f.uri},
                )
            )
        cmd = (f.cmdline or "").upper()
        if image == "svchost.exe" and "NETSVCS" in cmd and f.bytes_in > 0:
            out.append(
                Finding(
                    kind="moonbounce_netsvcs_fetch",
                    severity="medium",
                    summary="NETSVCS svchost fetched data from the network",
                    evidence={"dst": f"{f.dst_ip}:{f.dst_port}", "cmdline": f.cmdline,
                              "bytes_in": f.bytes_in,
                              "basis": "MoonBounce injects into SVCHOST.EXE -K NETSVCS",
                              "caution": EXTERNAL_ONLY_NOTES},
                )
            )
        if image == "rpcnetp.exe" and external:
            out.append(
                Finding(
                    kind="lojax_agent_egress",
                    severity="high",
                    summary="rpcnetp.exe originating external traffic",
                    evidence={"dst": f"{f.dst_ip}:{f.dst_port}",
                              "basis": "trojanised Computrace agent"},
                )
            )

    for d in dns:
        if d.qname.lower().rstrip(".") == "api.ipify.org":
            img = (d.image or "").lower()
            if "winlogon" in img:
                out.append(
                    Finding(
                        kind="blacklotus_ip_probe",
                        severity="high",
                        summary="winlogon.exe resolving api.ipify.org",
                        evidence={"qname": d.qname, "image": d.image,
                                  "basis": "documented BlackLotus public-IP check"},
                    )
                )
    return out


# ---------------------------------------------------------------------------
# Minimisation and evidence serialisation
# ---------------------------------------------------------------------------


def strip_query(uri: str | None) -> str | None:
    """Drop the query string. Paths are needed for detection; queries carry tokens."""
    if not uri:
        return uri
    return uri.split("?", 1)[0].split("#", 1)[0]


def minimise(record: DnsEvent | FlowEvent) -> dict:
    """Return a record reduced to the fields authorised for retention."""
    d = asdict(record)
    if "uri" in d:
        d["uri"] = strip_query(d["uri"])
    for k in ("payload", "body", "headers", "cookies", "query"):
        d.pop(k, None)
    if "qname" in d and d["qname"]:
        d["qname"] = d["qname"][:253].lower()
    return d


def _ts_ms(ts: float) -> int:
    return int(round(float(ts) * 1000))


def to_evidence(
    records: Sequence[DnsEvent | FlowEvent | ProcessNode],
) -> bytes:
    """Canonical, deterministic serialisation for sealing into the vault.

    Sorted and integer-millisecond timestamps so the same logical case always
    produces the same bytes, and therefore the same hash.
    """
    items = []
    for r in records:
        d = minimise(r) if not isinstance(r, ProcessNode) else asdict(r)
        if "ts" in d:
            d["ts_ms"] = _ts_ms(d.pop("ts"))
        items.append(d)

    def sort_key(d: dict) -> tuple:
        return (
            d.get("ts_ms", 0),
            d.get("host", ""),
            d.get("qname") or d.get("dst_ip") or d.get("image") or "",
            d.get("dst_port", 0),
        )

    items.sort(key=sort_key)
    return json.dumps(
        {"schema": "qvault.netobs.v1", "records": items},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

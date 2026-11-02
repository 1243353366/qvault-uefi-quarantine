"""LAN integrity and lateral movement monitor.

A LAN is a communication environment, not a machine. So the unit of analysis is a
*relationship* between devices with roles, not a device with a verdict.

Three rules shape this module:

  1. A BSSID is a label, not an identity. It can be copied. Authorisation binds to an
     authenticated identity (certificate fingerprint or keyed device identity), with the
     wireless label kept only as context.
  2. Metadata over content. TLS is not an obstacle to be removed: source, destination,
     timing, volume, service and DNS metadata are enough to reason about *relationships*,
     and none of it requires interception.
  3. Containment is graded and device-scoped. Every step names its blast radius, whether
     it is reversible, and how it is verified. A step that would affect more than one
     device, or that spreads material to other hosts, is refused: containment that
     propagates is an outbreak.

The hard question this exists to answer: can we show a device is behaving inconsistently
with its *authenticated identity* even when its own operating system is lying? Endpoint
evidence alone cannot, because the endpoint authors it. It takes at least two independent
layers, and firmware attestation is the only one that does not ask the device.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import findings as F
from . import limitations as L

# --- roles and least-privilege services -----------------------------------

WORKSTATION = "workstation"
SERVER = "server"
NAS = "nas"
PRINTER = "printer"
IOT = "iot"
AP = "ap"
ROUTER = "router"
SWITCH = "switch"
DNS = "dns"
DHCP = "dhcp"
BACKUP = "backup"
ADMIN = "admin"

ROLES = (WORKSTATION, SERVER, NAS, PRINTER, IOT, AP, ROUTER, SWITCH, DNS, DHCP, BACKUP, ADMIN)

SERVICE_NAMES = {
    22: "ssh", 23: "telnet", 53: "dns", 67: "dhcp", 80: "http", 123: "ntp",
    137: "netbios-ns", 139: "netbios-ssn", 443: "https", 445: "smb", 1900: "ssdp",
    2049: "nfs", 3389: "rdp", 5353: "mdns", 5900: "vnc", 9100: "print",
}

#: Service each role may legitimately initiate. Anything else is out-of-role and is a
#: lead, not a verdict: installers, backups and monitoring break role purity all the time.
class LanError(ValueError):
    """Malformed LAN input: refused by name, never silently dropped."""


ROLE_POLICY = {
    WORKSTATION: {53, 80, 443, 445, 123, 1900, 5353, 9100},
    SERVER: {53, 80, 443, 445, 123, 3389, 22, 2049},
    NAS: {53, 123, 445, 2049},
    PRINTER: {53, 123, 9100},
    IOT: {53, 123, 443},
    AP: {53, 123, 443, 80},
    ROUTER: {53, 123, 443},
    SWITCH: {53, 123, 443, 22},
    DNS: {53, 123},
    DHCP: {53, 67, 123},
    BACKUP: {445, 2049, 22, 443},
    ADMIN: {22, 443, 445, 3389, 5900},
}

#: Services that are remote-control or name-resolution primitives when seen east-west.
LATERAL_SERVICES = {445, 139, 3389, 22, 23, 5900, 2049, 135, 5985}


@dataclass(frozen=True)
class Device:
    """A network participant with an authenticated identity.

    `bssid` is deliberately last and deliberately not part of `identity_key`: binding
    authorisation to a wireless label is how a spoofed access point becomes trusted.
    """

    id: str
    role: str
    addr: str
    mac: str = ""
    cert_fp: str = ""
    bssid: str = ""
    firmware_attested: bool = False
    os_attested: bool = False
    managed: bool = True

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role!r}; known: {ROLES}")

    @property
    def identity_key(self) -> str:
        """The authenticated identity, never the wireless label."""
        if self.cert_fp:
            return f"cert:{self.cert_fp}"
        if self.mac:
            return f"mac:{self.mac}"
        raise ValueError(f"{self.id}: no authenticated identity; an address is not identity")

    @property
    def identity_strength(self) -> str:
        if self.cert_fp:
            return "certificate"
        if self.mac:
            return "hardware_address"
        return "address_only"


@dataclass(frozen=True)
class Flow:
    ts: int
    src: str
    dst: str
    port: int
    byte_count: int = 0
    encrypted: bool = True
    dns: str = ""
    fingerprint: str = ""

    @property
    def service(self) -> str:
        return SERVICE_NAMES.get(self.port, f"port-{self.port}")

    def key(self) -> str:
        """Identity of this observation, so copies cannot be counted twice."""
        if self.fingerprint:
            return self.fingerprint
        return f"{self.ts}:{self.src}>{self.dst}:{self.port}:{self.byte_count}"


@dataclass(frozen=True)
class AuthEvent:
    ts: int
    device: str
    principal: str
    credential: str
    result: str  # "success" | "failure"

    def __post_init__(self) -> None:
        if self.result not in ("success", "failure"):
            raise ValueError(f"result must be success or failure, not {self.result!r}")


@dataclass(frozen=True)
class DiscoveryEvent:
    ts: int
    device: str
    protocol: str  # mdns | llmnr | netbios | ssdp | upnp
    kind: str  # "query" | "response" | "advertise"
    target: str = ""
    designated: bool = False  # is this host the sanctioned responder for that protocol?

    def __post_init__(self) -> None:
        if self.protocol not in ("mdns", "llmnr", "netbios", "ssdp", "upnp"):
            raise ValueError(f"unknown discovery protocol {self.protocol!r}")
        if self.kind not in ("query", "response", "advertise"):
            raise ValueError(f"unknown discovery kind {self.kind!r}")


# --- baselines and deviation ----------------------------------------------


def deduplicate_flows(flows) -> tuple[list[Flow], int]:
    """Collapse repeated copies of one observation.

    A sensor that logs the same flow three times, or an attacker replaying records, must
    not look like three independent correlations.
    """
    seen: set[str] = set()
    out: list[Flow] = []
    dropped = 0
    for f in flows:
        k = f.key()
        if k in seen:
            dropped += 1
            continue
        seen.add(k)
        out.append(f)
    return out, dropped


def build_baseline(flows, *, min_observations: int = 3) -> dict:
    """Record which peers and services each device normally uses."""
    unique, _ = deduplicate_flows(flows)
    peers: dict[str, set[str]] = {}
    services: dict[str, set[int]] = {}
    for f in unique:
        peers.setdefault(f.src, set()).add(f.dst)
        services.setdefault(f.src, set()).add(f.port)
    baseline = {}
    for device, observed in services.items():
        baseline[device] = {
            "peers": peers.get(device, set()),
            "services": observed,
            "established": len(peers.get(device, ())) >= 1,
            "min_observations": min_observations,
        }
    return baseline


def deviations(flows, baseline) -> list[dict]:
    """New peers, new services, and out-of-role services.

    Every entry carries a benign reading, because the most common cause of all three is a
    new printer, a backup window, or someone installing a tool.
    """
    unique, _ = deduplicate_flows(flows)
    out: list[dict] = []
    for f in unique:
        known = baseline.get(f.src)
        if known is None:
            out.append({
                "kind": "first_contact",
                "device": f.src,
                "detail": f"no baseline for {f.src}",
                "service": f.service,
                "benign": "new or recently re-imaged device; baseline has not formed yet",
            })
            continue
        if f.dst not in known["peers"]:
            out.append({
                "kind": "new_peer",
                "device": f.src,
                "detail": f"{f.src} contacted {f.dst} which it has not contacted before",
                "service": f.service,
                "benign": "one-off transfer, guest device, or infrastructure change",
            })
        if f.port not in known["services"]:
            out.append({
                "kind": "new_service",
                "device": f.src,
                "detail": f"{f.src} used {f.service} ({f.port}) for the first time",
                "service": f.service,
                "benign": "software update, install, or a legitimate new tool",
            })
    return out


def out_of_role(flows, devices) -> list[dict]:
    """Traffic a role has no legitimate reason to initiate."""
    unique, _ = deduplicate_flows(flows)
    out = []
    for f in unique:
        dev = devices.get(f.src)
        if dev is None:
            continue
        allowed = ROLE_POLICY.get(dev.role, set())
        if f.port in allowed:
            continue
        out.append({
            "kind": "out_of_role",
            "device": f.src,
            "role": dev.role,
            "service": f.service,
            "detail": f"{dev.role} {f.src} initiated {f.service} to {f.dst}",
            "benign": "asset inventory wrong, or a sanctioned tool the policy has not learned",
            "suspicion_floor": "INFERRED" if f.port in LATERAL_SERVICES else "HYPOTHESIS",
        })
    return out



# --- discovery -------------------------------------------------------------

#: Protocols where an unsanctioned *response* is the interesting event, not a query.
POISONING_PROTOCOLS = ("llmnr", "netbios")


def discovery_anomalies(events) -> list[dict]:
    """Unusual local discovery behaviour.

    A query is normal: something is looking for a name. An unsanctioned *response* is a
    claim of authority over a name, which is how local name resolution gets hijacked.
    """
    out: list[dict] = []
    for e in events:
        if e.protocol in POISONING_PROTOCOLS and e.kind == "response" and not e.designated:
            out.append({
                "kind": "name_authority_claim",
                "device": e.device,
                "protocol": e.protocol,
                "detail": f"{e.device} answered a {e.protocol} query but is not the designated responder",
                "benign": "misconfigured host with a stale WINS/NBT service enabled",
                "grade": "INFERRED",
            })
        elif e.protocol in ("ssdp", "upnp") and e.kind == "advertise" and not e.designated:
            out.append({
                "kind": "unexpected_advertisement",
                "device": e.device,
                "protocol": e.protocol,
                "detail": f"{e.device} advertised via {e.protocol} without being a known media or IoT device",
                "benign": "consumer device, smart TV, or printer announcing itself",
                "grade": "HYPOTHESIS",
            })
        elif e.protocol == "mdns" and e.kind == "query" and not e.designated:
            out.append({
                "kind": "discovery_sweep",
                "device": e.device,
                "protocol": e.protocol,
                "detail": f"{e.device} issued an mDNS discovery query",
                "benign": "device pairing, AirPlay, or a printer driver searching",
                "grade": "HYPOTHESIS",
            })
    return out


# --- lateral movement ------------------------------------------------------


def lateral_movement(flows, auths, devices, *, window_s: int = 600) -> dict:
    """Correlate east-west service use with authentication failures.

    Independence is what raises this, not volume: one endpoint's log saying six things is
    one source. The layers counted here are distinct *kinds* of observation (network,
    authentication, role violation), and duplicates are collapsed first.
    """
    unique, dropped = deduplicate_flows(flows)
    east_west = [f for f in unique if f.port in LATERAL_SERVICES]
    failures = [a for a in auths if a.result == "failure"]
    successes_after = []
    for a in auths:
        if a.result != "success":
            continue
        prior = [x for x in failures if x.principal == a.principal and 0 <= a.ts - x.ts <= window_s]
        if prior:
            successes_after.append({"principal": a.principal, "device": a.device,
                                    "failures_before": len(prior)})

    layers = []
    if east_west:
        layers.append("network")
    if failures:
        layers.append("authentication")
    if successes_after:
        layers.append("authentication_after_failure")
    role_violations = out_of_role(unique, devices)
    if role_violations:
        layers.append("role_violation")

    grade = F.HYPOTHESIS
    if len(layers) >= 3:
        grade = F.CORROBORATED
    elif len(layers) == 2:
        grade = F.INFERRED

    return {
        "east_west_flows": len(east_west),
        "auth_failures": len(failures),
        "success_after_failure": successes_after,
        "role_violations": role_violations,
        "layers": layers,
        "independent_layers": len(layers),
        "duplicates_dropped": dropped,
        "grade": grade,
        "suspicion": len(layers) >= 2,
        "benign": "backup, admin tooling and monitoring all look like this at volume",
        "statement": (
            f"{len(layers)} independent layer(s) agree: {', '.join(layers) or 'none'}. "
            "One layer is a lead; two is a suspicion; three with an independent firmware "
            "anchor is the only shape that can survive a compromised endpoint."
        ),
    }


def infrastructure_integrity(devices) -> dict:
    """Network gear is a trust dependency, so it needs its own integrity model."""
    infra = [d for d in devices.values() if d.role in (AP, ROUTER, SWITCH, DNS, DHCP)]
    unattested = [d.id for d in infra if not d.firmware_attested]
    weak_identity = [d.id for d in infra if d.identity_strength == "hardware_address"]
    return {
        "infrastructure_devices": [d.id for d in infra],
        "firmware_unattested": unattested,
        "identity_bound_to_mac_only": weak_identity,
        "gaps": (
            [f"infra_firmware_unattested:{d}" for d in unattested]
            + [f"infra_identity_weak:{d}" for d in weak_identity]
        ),
        "statement": (
            "A compromised access point, router or resolver can affect every device it "
            "serves at once, so its integrity is not optional. Unattested infrastructure "
            "also cannot be trusted to enforce containment."
        ),
    }


def identity_inconsistency(layers: dict) -> dict:
    """The research question: is the device behaving unlike its authenticated identity?

    Endpoint evidence is authored by the endpoint. To claim inconsistency we need at least
    two independent layers, and to claim it *survived a compromised OS* we need firmware
    attestation, which does not ask the device.
    """
    independent = [name for name, present in layers.items() if present]
    firmware = bool(layers.get("firmware_attested"))
    os_compromised = bool(layers.get("endpoint_indicators"))
    net_deviation = bool(layers.get("lan_deviation"))

    # A string list cannot be counted for True: this fired never, which is the worst
    # possible failure for a rule that is supposed to gate a containment decision.
    other_layers = [n for n in independent if n != "lan_deviation"]
    if net_deviation and other_layers:
        if firmware and os_compromised:
            verdict = "inconsistent_with_identity"
            grade = F.CORROBORATED
        elif firmware:
            verdict = "inconsistent_with_identity"
            grade = F.INFERRED
        else:
            verdict = "unverified"
            grade = F.HYPOTHESIS
    else:
        verdict = "insufficient"
        grade = F.UNKNOWN

    return {
        "verdict": verdict,
        "grade": grade,
        "independent_layers": independent,
        "firmware_anchor": firmware,
        "os_compromised": os_compromised,
        "gaps": [] if firmware else ["no_firmware_anchor: the only layer that does not ask the device"],
        "statement": (
            "Inconsistent with its authenticated identity." if verdict == "inconsistent_with_identity"
            else "Cannot establish inconsistency: too few independent layers, or no anchor "
                 "outside the device itself." if verdict in ("unverified", "insufficient")
            else "Unclassified."
        ),
    }


# --- graded containment ----------------------------------------------------

#: Escalation ladder. Each step is narrower than the one above it in reversibility, and
#: every step is scoped to a single device by construction.
LADDER = (
    ("observe", "increase logging for the device and its peers", "seconds", True, 1),
    ("restrict_egress", "block the device's egress to the internet, keep LAN reachability", "minutes", True, 1),
    ("microsegment", "apply a per-device ACL denying east-west lateral services", "minutes", True, 1),
    ("revoke_credential", "revoke the device's credentials at the issuer", "minutes", False, 1),
    ("isolate_port", "disable the switch port or quarantine the VLAN membership", "seconds", True, 1),
    ("physical", "power off and escalate to out-of-band acquisition", "hours", False, 1),
)

#: Material that must never be pushed to other hosts as part of containment.
FORBIDDEN_PROPAGATION = ("credential", "key", "config", "agent_binary", "policy_bundle")


def containment_plan(assessment: dict, enforcement: dict) -> dict:
    """Recommend graded steps, and refuse the ones the enforcement plane cannot be trusted to carry out.

    `enforcement` describes the planes available, e.g.
    {"switch": {"trusted": False, "reason": "same vendor image as the compromised AP"}}.
    Asking a compromised switch to quarantine an attacker makes the attacker the jailer.
    """
    suspicious = assessment.get("suspicion") or assessment.get("verdict") == "inconsistent_with_identity"
    steps: list[dict] = []
    refusals: list[dict] = []

    for index, (name, action, latency, reversible, blast) in enumerate(LADDER):
        step = {
            "order": index,
            "step": name,
            "action": action,
            "latency": latency,
            "reversible": reversible,
            "blast_radius_devices": blast,
            "device_scoped": blast == 1,
            "requires": [],
            "verify_by": "two independent confirmations, one of which is not the device itself",
        }
        if name in ("isolate_port", "microsegment"):
            plane = enforcement.get("switch", {})
            if not plane.get("trusted", False):
                refusals.append({
                    "step": name,
                    "reason": plane.get("reason", "switch plane untrusted or unattested"),
                    "consequence": "containment must move to a plane the attacker does not control",
                    "alternatives": ["physical_disconnect", "upstream_port_disable", "revoke_credential"],
                })
                continue
            step["requires"].append("trusted_switch_plane")
        if name == "revoke_credential":
            step["requires"].append("issuer_reachable")
            step["verify_by"] = "issuer confirms revocation; the device's claim is not evidence"
        steps.append(step)

    return {
        "escalate": bool(suspicious),
        "steps": steps,
        "refused": refusals,
        "forbidden_actions": list(FORBIDDEN_PROPAGATION),
        "statement": (
            "Graded containment: smallest step that removes the dependency. Nothing here "
            "spreads material to another host, because containment that propagates is an outbreak."
        ),
    }


def assert_narrow(step: dict) -> None:
    """Containment may not become a broadcast."""
    if step.get("blast_radius_devices", 0) > 1:
        raise ValueError(
            f"step {step.get('step')!r} affects {step['blast_radius_devices']} devices; "
            "containment must be device-scoped, with wider action taken deliberately elsewhere"
        )
    if step.get("action_kind") in FORBIDDEN_PROPAGATION:
        raise ValueError(
            f"step {step.get('step')!r} would push {step['action_kind']} to other hosts"
        )


# --- cross-layer fusion ---------------------------------------------------


def _firmware_anchor(firmware: dict) -> tuple[bool, str]:
    """Whether firmware integrity is independently established.

    Accepts a firmware_integrity assessment or a plain subject->verdict map. Anything
    short of `match` on the flash image and the CRTM is not an anchor.
    """
    if not firmware:
        return False, "no firmware evidence supplied"
    if "host_trustworthy" in firmware:
        return bool(firmware["host_trustworthy"]), str(firmware.get("statement", ""))
    rows = firmware.get("rows") or []
    verdicts = {r.get("subject"): r.get("verdict") for r in rows}
    for subject, verdict in firmware.items():
        if isinstance(verdict, str):
            verdicts.setdefault(subject, verdict)
    needed = ("flash_image", "crtm")
    missing = [n for n in needed if verdicts.get(n) != "match"]
    if missing:
        return False, f"not established by an independent anchor: {', '.join(missing)}"
    return True, "flash image and CRTM match an independent reference"


def cross_layer(*, devices, flows, auths=(), discovery=(), firmware=None,
                endpoint_findings=(), provenance_gaps=()) -> dict:
    """Fuse firmware, endpoint, network, authentication and provenance evidence.

    Independence is the whole point: layers that all originate inside the suspect device
    are one layer wearing several names. The verdict is capped accordingly, and the
    strongest verdict additionally requires a firmware anchor, because everything else
    here was authored by the thing under suspicion.
    """
    devices = list(devices)
    by_id = {d.id: d for d in devices}
    flows, dup_flows = deduplicate_flows(list(flows))

    base = build_baseline(flows)
    devs = deviations(flows, base)
    role = out_of_role(flows, by_id)
    disc = discovery_anomalies(list(discovery))
    lat = lateral_movement(flows, list(auths), by_id)
    infra = infrastructure_integrity(by_id)
    anchored, anchor_note = _firmware_anchor(firmware or {})

    endpoint_positive = bool(endpoint_findings)
    net_delta = bool(devs or role or disc or lat.get("suspicion"))

    ident = identity_inconsistency({
        "lan_deviation": net_delta,
        "endpoint_indicators": endpoint_positive,
        "firmware_attested": anchored,
    })

    layers = {
        "network": net_delta,
        "authentication": bool(auths),
        "endpoint": endpoint_positive,
        "firmware": anchored,
        "provenance": not provenance_gaps,
    }
    independent = [n for n, v in layers.items() if v]

    gaps = list(provenance_gaps)
    if not anchored:
        gaps.append(f"firmware_unattested: {anchor_note}")
    if not devices:
        gaps.append("no network inventory: role violations cannot be assessed")
    if not flows:
        gaps.append("no traffic: baseline and deviation are unmeasured, not clean")
    gaps.extend(infra.get("gaps", []))

    # Two separate claims, graded separately. "This host violated its role" rests on
    # network evidence and needs no firmware anchor. "This device is inconsistent with
    # its authenticated identity" is a claim about identity and does need one. Coupling
    # them let an unrelated gap erase a real role violation, which is under-reporting.
    if ident["verdict"] == "inconsistent_with_identity":
        grade = F.CORROBORATED
    elif role or lat.get("suspicion"):
        grade = F.CORROBORATED if len(independent) >= 2 else F.INFERRED
    elif devs or disc:
        grade = F.INFERRED if independent else F.HYPOTHESIS
    else:
        grade = F.UNKNOWN
    # Gaps cost one step at most: a missing anchor weakens, it does not erase.
    if provenance_gaps and grade != F.UNKNOWN:
        grade = F.confidence_grade(grade, tuple(gaps))

    if grade in (F.CONFIRMED, F.CORROBORATED, F.INFERRED):
        verdict = "suspicious"
    elif grade == F.UNKNOWN and independent:
        verdict = "inconclusive"
    elif not independent:
        verdict = F.INCONCLUSIVE
    else:
        verdict = F.NO_EVIDENCE_FOUND

    return {
        "verdict": verdict,
        "grade": grade,
        "identity": ident,
        "layers_present": independent,
        "independent_layers": len(independent),
        "flows": len(flows),
        "duplicate_flows_dropped": dup_flows,
        "deviations": devs,
        "role_violations": role,
        "discovery": disc,
        "lateral": lat,
        "infrastructure": infra,
        "gaps": gaps,
        "statement": (
            f"{len(independent)} independent layer(s) of evidence; verdict {verdict} "
            f"at grade {grade}. This is not a statement that the network is clean."
        ),
    }


def load_case(doc: dict) -> dict:
    """Parse a LAN case file into the inputs cross_layer takes.

    Deliberately strict: an unknown role or a malformed flow is refused with the field
    named, because silently dropping hostile records is how a case file under-reports.
    """
    if not isinstance(doc, dict):
        raise LanError("a case file must be a JSON object")
    try:
        devices = [
            Device(id=d["id"], role=d["role"], addr=d.get("addr", ""),
                   mac=d.get("mac", ""), bssid=d.get("bssid", ""),
                   cert_fp=d.get("cert_fp", ""),
                   firmware_attested=bool(d.get("firmware_attested", False)),
                   os_attested=bool(d.get("os_attested", False)))
            for d in doc.get("devices", [])
        ]
        flows = [
            Flow(ts=int(f["ts"]), src=f["src"], dst=f["dst"], port=int(f["port"]),
                 byte_count=int(f.get("byte_count", f.get("bytes", 0))),
                 encrypted=bool(f.get("encrypted", True)),
                 dns=f.get("dns", ""), fingerprint=f.get("fingerprint", ""))
            for f in doc.get("flows", [])
        ]
        auths = [
            AuthEvent(ts=int(a["ts"]), device=a["device"], principal=a["principal"],
                      credential=a.get("credential", ""), result=a["result"])
            for a in doc.get("auths", [])
        ]
        discovery = [
            DiscoveryEvent(ts=int(e["ts"]), device=e["device"], protocol=e["proto"],
                           kind=e["kind"], target=e.get("target", ""),
                           designated=bool(e.get("designated", False)))
            for e in doc.get("discovery", [])
        ]
    except (KeyError, TypeError, ValueError) as exc:
        raise LanError(f"malformed case file: {exc}") from exc
    return {
        "devices": devices, "flows": flows, "auths": auths, "discovery": discovery,
        "firmware": doc.get("firmware") or {},
        "endpoint_findings": doc.get("endpoint_findings") or [],
        "provenance_gaps": doc.get("provenance_gaps") or [],
        "enforcement": doc.get("enforcement") or {},
    }

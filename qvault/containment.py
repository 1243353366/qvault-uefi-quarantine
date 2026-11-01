"""
qvault.containment
==================

The six capability denials, and the honest question: who enforces it?

The proposal
------------
Deny a suspected subject access to network resources, authentication services,
storage, compute resources, inter-network communication and decryption
capabilities. As a list of goals, sound. As a list of controls, it is only as real
as the layer enforcing each one.

The problem
-----------
Every one of these is enforceable at several layers, and they are not equivalent:

* **Subject OS** — firewall rules, ACLs, AppLocker, SELinux, service disablement.
  Enforced by the thing you suspect. Against a compromised kernel this is not a
  weak control, it is a *removed* one: the attacker's own code decides whether the
  rule applies. Against an implant resident in SPI flash or SMM it never runs at
  all, because the implant's code executes before the OS exists.
* **Hypervisor** — enforcement outside the guest. Holds against a compromised
  guest OS, which is the whole point of a hypervisor. Does not hold against
  compromised firmware: SMM and DXE act beneath the hypervisor.
* **Fabric** — switch ACLs, VLAN isolation, port shutdown. Enforced by equipment
  the subject does not control, so it survives any host compromise. Requires every
  egress path to be enumerated; one forgotten radio defeats it.
* **Physical** — cable out, power off, disk removed, write-blocker fitted. Survives
  everything, at the cost of your ability to observe.
* **Cryptographic** — the capability is absent because the material is absent. The
  only mechanism here that does not depend on the subject's cooperation, its
  firmware, or its hypervisor.

So a denial is modelled as (capability, plane, mechanism), coverage is computed per
subject posture, and the module will tell you when your plan does not support the
claim you want to make. Containment is not eradication: nothing here removes an
implant from flash.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Capabilities under discussion.
NETWORK = "network"
AUTH_SERVICES = "auth_services"
STORAGE = "storage"
COMPUTE = "compute"
INTER_NETWORK = "inter_network"
DECRYPTION = "decryption"

CAPABILITIES = (NETWORK, AUTH_SERVICES, STORAGE, COMPUTE, INTER_NETWORK, DECRYPTION)

# Enforcement planes.
SUBJECT_OS = "subject_os"
HYPERVISOR = "hypervisor"
FIRMWARE_PLATFORM = "firmware_platform"
FABRIC = "fabric"
PHYSICAL = "physical"
CRYPTOGRAPHIC = "cryptographic"

PLANES = (SUBJECT_OS, HYPERVISOR, FIRMWARE_PLATFORM, FABRIC, PHYSICAL, CRYPTOGRAPHIC)

# What the subject is assumed to control.
CLEAN_HOST = "clean_host"
COMPROMISED_OS = "compromised_os"
COMPROMISED_FIRMWARE = "compromised_firmware"

POSTURES = (CLEAN_HOST, COMPROMISED_OS, COMPROMISED_FIRMWARE)

FULL, PARTIAL, NONE, NA = "full", "partial", "none", "not_applicable"
_RANK = {NA: 0, NONE: 1, PARTIAL: 2, FULL: 3}

# Coverage of a plane, per subject posture.
# Readings of this table are the argument of the module, so each cell is justified
# in PLANE_NOTES below rather than left implicit.
COVERAGE: dict[tuple[str, str], str] = {
    (SUBJECT_OS, CLEAN_HOST): FULL,
    (SUBJECT_OS, COMPROMISED_OS): NONE,
    (SUBJECT_OS, COMPROMISED_FIRMWARE): NONE,
    (HYPERVISOR, CLEAN_HOST): FULL,
    (HYPERVISOR, COMPROMISED_OS): FULL,
    (HYPERVISOR, COMPROMISED_FIRMWARE): PARTIAL,
    (FIRMWARE_PLATFORM, CLEAN_HOST): PARTIAL,
    (FIRMWARE_PLATFORM, COMPROMISED_OS): NONE,
    (FIRMWARE_PLATFORM, COMPROMISED_FIRMWARE): NONE,
    (FABRIC, CLEAN_HOST): FULL,
    (FABRIC, COMPROMISED_OS): FULL,
    (FABRIC, COMPROMISED_FIRMWARE): FULL,
    (PHYSICAL, CLEAN_HOST): FULL,
    (PHYSICAL, COMPROMISED_OS): FULL,
    (PHYSICAL, COMPROMISED_FIRMWARE): FULL,
    (CRYPTOGRAPHIC, CLEAN_HOST): FULL,
    (CRYPTOGRAPHIC, COMPROMISED_OS): FULL,
    (CRYPTOGRAPHIC, COMPROMISED_FIRMWARE): FULL,
}

PLANE_NOTES = {
    SUBJECT_OS: (
        "enforced by the thing under suspicion; a compromised kernel removes it and a "
        "firmware implant never runs it"
    ),
    HYPERVISOR: (
        "outside the guest, so it survives OS compromise; SMM and DXE act beneath it, so "
        "it does not survive firmware compromise"
    ),
    FIRMWARE_PLATFORM: (
        "BIOS passwords, boot order, lock bits: configuration, not enforcement, and not "
        "resistant to an attacker already in firmware"
    ),
    FABRIC: (
        "enforced by equipment the subject does not control; effective at any posture "
        "provided every egress path is enumerated"
    ),
    PHYSICAL: (
        "cable out, power off, media removed; effective at any posture and destroys "
        "observability while it is in force"
    ),
    CRYPTOGRAPHIC: (
        "the capability is absent because the key is absent; the only mechanism that does "
        "not depend on the subject behaving"
    ),
}

# Egress paths that must all be accounted for before a fabric denial counts as full
# for network reachability.
EGRESS_PATHS = frozenset({"wired", "wireless", "cellular", "bluetooth", "peripheral_dma"})


@dataclass(frozen=True)
class Denial:
    capability: str
    plane: str
    mechanism: str
    covers_paths: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.capability not in CAPABILITIES:
            raise ValueError(f"unknown capability {self.capability!r}")
        if self.plane not in PLANES:
            raise ValueError(f"unknown plane {self.plane!r}")


@dataclass
class Plan:
    denials: list[Denial] = field(default_factory=list)

    def add(self, denial: Denial) -> "Plan":
        self.denials.append(denial)
        return self

    def for_capability(self, capability: str) -> list[Denial]:
        return [d for d in self.denials if d.capability == capability]

    def to_dict(self) -> dict:
        return {
            "denials": [
                {
                    "capability": d.capability,
                    "plane": d.plane,
                    "mechanism": d.mechanism,
                    "covers_paths": sorted(d.covers_paths),
                }
                for d in self.denials
            ]
        }


def _coverage(denial: Denial, posture: str) -> tuple[str, str]:
    """Coverage of a single denial at a posture, with the reason it falls short."""
    base = COVERAGE[(denial.plane, posture)]

    # Cryptographic enforcement is only meaningful for the decryption capability.
    if denial.plane == CRYPTOGRAPHIC and denial.capability != DECRYPTION:
        return NA, "cryptography does not deny this capability"
    if denial.capability == DECRYPTION and denial.plane != CRYPTOGRAPHIC:
        # No other plane can deny a decryption capability; they can only deny the
        # ability to reach the ciphertext.
        if denial.plane in (PHYSICAL, FABRIC, HYPERVISOR):
            return PARTIAL, (
                "denies reach to the ciphertext, not the capability; anyone who obtains "
                "the object and the key still decrypts"
            )
        return NONE, "does not affect decryption"

    # A fabric denial of reachability is only as good as its path enumeration.
    if denial.plane == FABRIC and denial.capability in (NETWORK, INTER_NETWORK):
        missing = EGRESS_PATHS - denial.covers_paths
        if missing:
            return PARTIAL, f"unenumerated egress paths: {', '.join(sorted(missing))}"

    if base == NONE:
        return NONE, PLANE_NOTES[denial.plane]
    if base == PARTIAL:
        return PARTIAL, PLANE_NOTES[denial.plane]
    return FULL, PLANE_NOTES[denial.plane]


def assess(plan: Plan, posture: str) -> dict:
    """Compute what the plan actually denies at a given subject posture."""
    if posture not in POSTURES:
        raise ValueError(f"unknown posture {posture!r}")

    rows = []
    uncovered = []
    partial = []

    for cap in CAPABILITIES:
        denials = plan.for_capability(cap)
        best = NONE
        best_by: list[str] = []
        notes: list[str] = []
        for d in denials:
            status, why = _coverage(d, posture)
            if status == NA:
                continue
            if _RANK[status] > _RANK[best]:
                best = status
                best_by = [f"{d.plane}: {d.mechanism}"]
                notes = [why]
            elif status == best:
                if status != NONE:
                    best_by.append(f"{d.plane}: {d.mechanism}")
                    notes.append(why)
                elif not notes:
                    # An ineffective denial must still explain itself: "the firewall
                    # is enforced by the compromised host" is the useful answer, and
                    # "no denial specified" would be a lie.
                    notes = [f"ineffective: {why}"]
        row = {
            "capability": cap,
            "status": best,
            "enforced_by": best_by,
            "note": notes[0] if notes else "no denial specified",
        }
        rows.append(row)
        if best == NONE:
            uncovered.append(cap)
        elif best == PARTIAL:
            partial.append(cap)

    return {
        "posture": posture,
        "rows": rows,
        "fully_denied": [r["capability"] for r in rows if r["status"] == FULL],
        "partially_denied": partial,
        "not_denied": uncovered,
        "eradicates": False,
        "statements": [
            "Capability denial bounds what the subject can do; it removes nothing.",
            "A firmware-resident implant survives every denial listed here; only "
            "reflashing or replacement addresses that.",
            "Subject-OS enforcement is excluded from the count at compromised postures, "
            "because the subject decides whether its own rules apply.",
        ],
    }


def audit_claim(plan: Plan, posture: str, claimed: list[str]) -> list[dict]:
    """Check a claim of the form 'we denied X, Y and Z' against the plan.

    Returns one entry per capability the plan does not support at this posture.
    An empty list means the claim holds.
    """
    unknown = [c for c in claimed if c not in CAPABILITIES]
    if unknown:
        raise ValueError(f"unknown capabilities in claim: {unknown}")

    result = assess(plan, posture)
    status = {r["capability"]: r for r in result["rows"]}
    violations = []
    for cap in claimed:
        row = status[cap]
        if row["status"] == FULL:
            continue
        violations.append(
            {
                "capability": cap,
                "claimed": "denied",
                "actual": row["status"],
                "why": row["note"],
                "enforced_by": row["enforced_by"],
            }
        )
    return violations


def reference_plan() -> Plan:
    """A plan that is honest at the firmware-compromised posture.

    Every capability is denied by a plane that does not depend on the subject's own
    code: fabric for reachability, hypervisor where isolation is needed, physical for
    compute, cryptography for decryption.
    """
    plan = Plan()
    plan.add(Denial(NETWORK, FABRIC, "port ACL: deny all egress except the capture VLAN",
                    covers_paths=EGRESS_PATHS))
    plan.add(Denial(INTER_NETWORK, FABRIC, "VLAN isolation, no inter-VLAN routing",
                    covers_paths=EGRESS_PATHS))
    plan.add(Denial(AUTH_SERVICES, FABRIC, "no route to IdP/KDC/CA networks",
                    covers_paths=EGRESS_PATHS))
    plan.add(Denial(STORAGE, HYPERVISOR, "no virtual disk attached; read-only share if any"))
    plan.add(Denial(STORAGE, PHYSICAL, "no storage media present in the subject"))
    plan.add(Denial(COMPUTE, PHYSICAL, "powered off; no boot device present"))
    plan.add(Denial(DECRYPTION, CRYPTOGRAPHIC, "no key material on the subject or its storage"))
    return plan

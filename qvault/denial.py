"""Three ways to deny an attacker, and what each one actually guarantees.

The three postures are not interchangeable, and none of them is a verdict:

    deny_access      the payload exists but is unusable (encryption without the key)
    deny_capability  the code exists but cannot reach what it needs (isolation)
    deny_execution   the code exists on disk but cannot start (verified-boot allow list)

Each is a statement about an adversary's *inability*, and inability is the hardest thing to
establish from inside the system being attacked. So this module grades the claim a posture
supports and, just as importantly, records the condition under which the denial ends. A denial
with no stated expiry is a belief, not a control.

The ceiling rule: no posture reaches CONFIRMED. CONFIRMED is reserved for things observable in
the evidence. "The attacker cannot" is not observable, it is inferred from the absence of a
success, and absence of evidence is exactly what this project refuses to promote.

This module does not produce verdicts. The verdict engine stays single-owner; this grades claims
about controls and uses the shared grade vocabulary from `findings`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import findings as F


class DenialError(ValueError):
    """Raised when a posture is unknown or an assessment is asked for without its inputs."""


#: Enforcement planes, strongest first. A control is only as strong as the plane it sits on, and
#: a plane inside the thing being attacked is a preference, not an enforcement.
PLANES = (
    "hardware",        # SPI write protect, TPM-held keys, physical disconnection
    "external_key",    # key custody outside the host's trust domain
    "out_of_band",     # a different machine or a switch port the host cannot reprogram
    "supply_chain",    # a signed revocation that has actually been applied (dbx, SBAT)
    "in_band",         # policy running on the host it is meant to constrain
    "absent",          # asserted with no enforcement at all
)

#: The strongest grade each plane can support for a claim of denial.
PLANE_CEILING = {
    "hardware": F.CORROBORATED,
    "external_key": F.CORROBORATED,
    "out_of_band": F.CORROBORATED,
    "supply_chain": F.CORROBORATED,
    "in_band": F.INFERRED,
    "absent": F.UNKNOWN,
}


@dataclass(frozen=True)
class Posture:
    """One denial posture, including the part that is usually left out: what it does not do."""

    name: str
    denies: str
    load_bearing: str
    stops: tuple[str, ...]
    does_not_stop: tuple[str, ...]
    restored_when: str
    availability_cost: str
    admissible_planes: tuple[str, ...] = field(default=PLANES)


POSTURES: tuple[Posture, ...] = (
    Posture(
        name="deny_access",
        denies="the payload is usable: the bytes are there, the key is not",
        load_bearing="key custody, plus the proof that the key never lived beside the ciphertext",
        stops=(
            "a payload encrypted before an attacker arrived being read afterwards",
            "exfiltration of the ciphertext turning into execution, while the key is withheld",
            "an analyst or an automated tool decrypting evidence without quorum",
        ),
        does_not_stop=(
            "a key that was already copied while it was available",
            "plaintext an attacker kept before encryption happened",
            "an implant that never needed the payload: a bootkit in SPI flash is not encrypted",
            "the attacker waiting: access is denied for a window, not for good",
        ),
        restored_when="the key becomes available inside the attacker's reach, at which point the "
                      "payload is as readable as it was before",
        availability_cost="lose the key and the evidence or the data is gone; this is the one "
                          "posture whose failure mode is unrecoverable by design",
    ),
    Posture(
        name="deny_capability",
        denies="the code reaches what it needs: execution, communication, persistence",
        load_bearing="the completeness of the resource enumeration, which is ours and not the attacker's",
        stops=(
            "a driver talking to a device it is no longer on the same bus as",
            "an implant beaconing out of a host with no route, or a port that is down",
            "persistence across reboot when the write target is protected below the OS",
        ),
        does_not_stop=(
            "a capability we did not think of; isolation only removes what is on our list",
            "code that still runs and adapts inside the reduced space",
            "an attacker who moves to a host that is not isolated",
            "detection: a quiet implant on an isolated host is quieter, not absent",
        ),
        restored_when="the isolation is lifted, or the attacker finds a path that was never in the "
                      "enumeration, and the capability returns without any alarm having fired",
        availability_cost="reduced observability: the same boundary that starves the malware also "
                          "starves the telemetry that would have caught it",
    ),
    Posture(
        name="deny_execution",
        denies="the code starts: on disk, unverified, and unable to run",
        load_bearing="the verification root being outside the control of the code being verified",
        stops=(
            "an unsigned or revoked boot component on a chain anchored in hardware",
            "a userland binary outside the allow list, where the kernel enforcing it is itself trusted",
            "a bootkit whose revocation has actually been applied",
        ),
        does_not_stop=(
            "code verified on a chain the attacker controls below the verifier",
            "a signed component that is legitimately signed and malicious, which verification "
            "cannot see by construction",
            "a revocation nobody shipped: an unapplied dbx denies nothing",
            "anything already running before verification was enabled",
        ),
        restored_when="the verifier's root is compromised, or the allow list is stale against a "
                      "signed-but-hostile component, and execution is permitted by policy",
        availability_cost="a wrong allow list or a bad revocation update bricks the machine; the "
                          "denial is only as good as the update pipeline behind it",
    ),
)

BY_NAME = {p.name: p for p in POSTURES}


def assert_complete() -> None:
    """Every posture must state its plane, its non-claims, its expiry and its cost."""
    problems = []
    for posture in POSTURES:
        if len(posture.stops) < 1:
            problems.append(f"{posture.name}: no stops listed")
        if len(posture.does_not_stop) < 3:
            problems.append(f"{posture.name}: fewer than three non-claims; the list is the point")
        if not posture.restored_when.strip():
            problems.append(f"{posture.name}: no stated condition under which denial ends")
        if not posture.availability_cost.strip():
            problems.append(f"{posture.name}: no availability cost stated")
        if not posture.load_bearing.strip():
            problems.append(f"{posture.name}: no load-bearing control named")
        if "in_band" not in posture.admissible_planes:
            problems.append(f"{posture.name}: no in-band plane declared, so the weak case is hidden")
    if {p.name for p in POSTURES} != {"deny_access", "deny_capability", "deny_execution"}:
        problems.append("the set of postures has drifted from the three the model defines")
    if any(PLANE_CEILING[p] == F.CONFIRMED for p in PLANES):
        problems.append("a denial plane claims CONFIRMED; inability is not observable")
    if problems:
        raise DenialError("; ".join(problems))


def assess(posture: str, *, plane: str, corroborating_evidence: int = 0,
           enforced_by_target: bool = True) -> dict:
    """Grade a claim that a posture is holding.

    `enforced_by_target` is the question that decides most of these: is the control on the same
    machine as the thing it constrains? If yes, a compromise of that machine is a compromise of
    the control, and the claim caps at INFERRED however many green ticks the console shows.
    """
    if posture not in BY_NAME:
        raise DenialError(f"unknown posture {posture!r}; known: {sorted(BY_NAME)}")
    if plane not in PLANES:
        raise DenialError(f"unknown plane {plane!r}; known: {PLANES}")
    if corroborating_evidence < 0:
        raise DenialError("corroborating_evidence cannot be negative")

    spec = BY_NAME[posture]
    if plane not in spec.admissible_planes:
        raise DenialError(f"{posture} cannot be enforced on {plane!r}")

    limit = PLANE_CEILING[plane]
    if enforced_by_target and plane != "hardware":
        limit = _lower(limit, F.INFERRED)

    proposed = _proposed(corroborating_evidence)
    grade = _lower(proposed, limit)
    grade = _lower(grade, F.CORROBORATED)  # never CONFIRMED; inability is not observable

    if limit == F.UNKNOWN:
        reason = f"no enforcement plane: a {posture} claim asserted without one grades {grade}"
    elif enforced_by_target and plane != "hardware":
        reason = (f"enforced by the target itself, so a compromise of the host is a compromise "
                  f"of the control: {proposed} proposed, capped to {limit}")
    else:
        reason = f"{proposed} proposed, within the {plane} ceiling {limit}"

    return {
        "posture": posture,
        "claim": spec.denies,
        "grade": grade,
        "proposed": proposed,
        "ceiling": limit,
        "plane": plane,
        "enforced_by_target": enforced_by_target,
        "reason": reason,
        "non_claim": spec.does_not_stop,
        "restored_when": spec.restored_when,
        "availability_cost": spec.availability_cost,
        "load_bearing": spec.load_bearing,
    }


#: Which plane each posture must be on to be worth composing, and what a shared plane costs.
COMPOSITION = (
    ("deny_access + deny_execution on the same plane",
     "collapses into one control: a key held by the same authority that signs the allow list is "
     "one compromise away from both"),
    ("deny_capability + deny_execution across planes",
     "independent: starvation is enforced on the network, execution on the boot chain, so one "
     "compromise does not lift the other"),
    ("all three on the target OS",
     "none of them hold against a kernel-level compromise; they describe a machine that is still "
     "trusted, which is the assumption a bootkit removes"),
)


#: What a quantity of corroborating observation proposes, before the plane caps it. A posture with
#: no corroboration is a hypothesis however confident the console looks; three independent
#: observations is as strong as a claim about inability can get.
PROPOSED_GRADES = ((0, F.HYPOTHESIS), (1, F.HYPOTHESIS), (2, F.INFERRED), (3, F.CORROBORATED))


def _proposed(corroborating_evidence: int) -> str:
    for threshold, grade in PROPOSED_GRADES:
        if corroborating_evidence <= threshold:
            return grade
    return PROPOSED_GRADES[-1][1]


#: Strongest first, matching `findings.GRADES`. Lower index is a stronger claim.
_RANK = {grade: index for index, grade in enumerate(F.GRADES)}


def _lower(a: str, b: str) -> str:
    """The weaker of two grades. A ceiling is a limit, so the weaker claim wins."""
    return a if _RANK[a] >= _RANK[b] else b

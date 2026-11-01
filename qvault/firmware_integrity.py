"""
qvault.firmware_integrity
=========================

A separate subsystem, because an OS scan cannot certify the hardware that hosts it.

The principle
-------------
An operating-system scan runs on the machine it is judging, is executed by a kernel
the implant may be inside, and reports through drivers the firmware may be lying to.
It therefore cannot establish that UEFI firmware, the boot chain or device firmware is
trustworthy. This is not a confidence problem to be improved with more coverage; it
is a direction problem. The evidence route decides the question before the scan
starts.

So firmware integrity is not a check in the device-artifact toolkit. It is its own
subsystem with its own evidence model, and the central rule is:

    **A verdict may not be stronger than the anchor that produced it.**

Anchors, weakest to strongest, and what each can establish
----------------------------------------------------------
`os_mediated` (0)
    In-band read through the subject's kernel. Establishes **nothing** about
    firmware. An implant answering the read reports whatever it wants.

`pre_os_measured` (1)
    Measurement by the firmware itself during boot. Establishes at most a hypothesis:
    the thing being measured is doing the measuring.

`tpm_quote` (2)
    PCR quote against a known-good policy. Genuinely useful, and it does **not**
    establish flash integrity or CRTM integrity: measurement starts at the CRTM, so a
    compromised CRTM measures itself and the quote still verifies. It detects
    post-CRTM tampering only.

`hardware_boot_rom` (3)
    Immutable boot ROM verifying the first stage (Boot Guard-style). Can establish
    the CRTM, subject to the vendor key and fuse state, neither of which this code can
    inspect.

`oob_flash_read` (4)
    Out-of-band read of the SPI device. The only anchor that can establish what is
    actually in flash, because it does not ask the subject.

Host trust requires `flash_image` and `crtm` to match under anchors strong enough to
establish them. A TPM quote that says the boot was clean does not make the host
trustworthy, and this module will not pretend otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import findings as F

# --- verdicts -------------------------------------------------------------

MATCH = "match"
MISMATCH = "mismatch"
INCONCLUSIVE = "inconclusive"
UNATTESTED = "unattested"

VERDICTS = (MATCH, MISMATCH, INCONCLUSIVE, UNATTESTED)

# --- subjects -------------------------------------------------------------

CRTM = "crtm"
FLASH_IMAGE = "flash_image"
BOOT_CHAIN = "boot_chain"
DXE_DRIVERS = "dxe_drivers"
OPTION_ROM = "option_rom"
EC_ME = "ec_me"

SUBJECTS = (CRTM, FLASH_IMAGE, BOOT_CHAIN, DXE_DRIVERS, OPTION_ROM, EC_ME)

# Subjects that must be established before a host may be called trustworthy, and the
# minimum anchor rank that can establish each. Note that flash_image has exactly one
# admissible anchor: there is no in-band route to it.
REQUIRED_FOR_TRUST: dict[str, int] = {
    FLASH_IMAGE: 3,   # hardware_boot_rom or oob_flash_read
    CRTM: 3,
}

# Subjects worth tracking that do not block a trust verdict, reported as unattested.
TRACKED_NOT_REQUIRED = (BOOT_CHAIN, DXE_DRIVERS, OPTION_ROM, EC_ME)


_GRADE_RANK = {F.UNKNOWN: 0, F.HYPOTHESIS: 1, F.INFERRED: 2, F.CORROBORATED: 3, F.CONFIRMED: 4}
_RANK_GRADE = {v: k for k, v in _GRADE_RANK.items()}


class IntegrityError(ValueError):
    """Raised when a firmware verdict would exceed its evidence."""


@dataclass(frozen=True)
class Anchor:
    name: str
    rank: int
    establishes: frozenset[str]
    grade: str
    caveat: str


ANCHORS: dict[str, Anchor] = {
    "os_mediated": Anchor(
        "os_mediated", 0, frozenset(), F.UNKNOWN,
        "read through the subject; the implant authors the answer, so this "
        "establishes nothing about firmware",
    ),
    "pre_os_measured": Anchor(
        "pre_os_measured", 1, frozenset({BOOT_CHAIN, DXE_DRIVERS}), F.HYPOTHESIS,
        "the firmware measures itself: a hypothesis, not evidence",
    ),
    "tpm_quote": Anchor(
        "tpm_quote", 2, frozenset({BOOT_CHAIN, DXE_DRIVERS, OPTION_ROM}), F.CORROBORATED,
        "measurement begins at the CRTM, so a compromised CRTM measures itself and "
        "the quote still verifies; detects post-CRTM tampering only",
    ),
    "hardware_boot_rom": Anchor(
        "hardware_boot_rom", 3, frozenset({CRTM, BOOT_CHAIN}), F.CORROBORATED,
        "immutable ROM verifies the first stage; trust depends on the vendor key and "
        "fuse state, which this module cannot inspect",
    ),
    "oob_flash_read": Anchor(
        "oob_flash_read", 4,
        frozenset({FLASH_IMAGE, CRTM, DXE_DRIVERS, EC_ME, OPTION_ROM}), F.CORROBORATED,
        "does not ask the subject; read-back equivalence for in-circuit reads is "
        "unverified (H8), so a single read is corroborated rather than confirmed",
    ),
}

#: Retained for clarity: the one anchor that may never support a firmware verdict.
INADMISSIBLE_ANCHORS = frozenset({"os_mediated"})


def anchor_rank(name: str) -> int:
    if name not in ANCHORS:
        raise IntegrityError(f"unknown anchor {name!r}; known: {sorted(ANCHORS)}")
    return ANCHORS[name].rank


def admits(name: str) -> bool:
    """Whether an anchor may contribute to a firmware verdict at all."""
    anchor_rank(name)  # validates
    return name not in INADMISSIBLE_ANCHORS and bool(ANCHORS[name].establishes)


def grade_for(name: str, *, independent_sources: int = 1) -> str:
    """Evidence grade an anchor can support, before read-equivalence penalties."""
    anchor = ANCHORS[name]
    if name in INADMISSIBLE_ANCHORS:
        return F.UNKNOWN
    if independent_sources >= 2 and anchor.grade in (F.INFERRED, F.CORROBORATED):
        return F.CONFIRMED
    return anchor.grade


@dataclass(frozen=True)
class FirmwareEvidence:
    """One observation about one subject, from one anchor."""

    anchor: str
    subject: str
    verdict: str
    reference_id: str = ""
    reference_trusted: bool = True
    equivalence_verified: bool = True

    def __post_init__(self) -> None:
        anchor_rank(self.anchor)
        if self.subject not in SUBJECTS:
            raise IntegrityError(f"unknown subject {self.subject!r}; known: {SUBJECTS}")
        if self.verdict not in VERDICTS:
            raise IntegrityError(f"unknown verdict {self.verdict!r}; known: {VERDICTS}")


def _effective(ev: FirmwareEvidence) -> tuple[str, str, str]:
    """Resolve one piece of evidence to (verdict, grade, reason)."""
    if not admits(ev.anchor):
        return UNATTESTED, F.UNKNOWN, ANCHORS[ev.anchor].caveat
    if ev.subject not in ANCHORS[ev.anchor].establishes:
        return (
            UNATTESTED, F.UNKNOWN,
            f"{ev.anchor} cannot establish {ev.subject}: {ANCHORS[ev.anchor].caveat}",
        )
    if ev.verdict == UNATTESTED:
        return UNATTESTED, F.UNKNOWN, "no observation recorded"
    if not ev.reference_trusted:
        return (
            INCONCLUSIVE, F.UNKNOWN,
            "compared against an untrusted reference: 'match' would mean only that it "
            "matched something unknown",
        )
    grade = grade_for(ev.anchor)
    if ev.anchor == "oob_flash_read" and not ev.equivalence_verified:
        grade = F.confidence_grade(grade, ("read_equivalence_unverified",))
    return ev.verdict, grade, ANCHORS[ev.anchor].caveat


def assess(evidence) -> dict:
    """Per-subject verdicts, with the anchor each rests on.

    Worst case wins: any mismatch in a subject makes that subject `mismatch`, because
    one dissenting anchor outweighs agreeing ones that may share a blind spot.
    """
    evidence = list(evidence)
    rows = []
    mismatched: list[str] = []
    unattested: list[str] = []

    for subject in SUBJECTS:
        considered = [ev for ev in evidence if ev.subject == subject]
        resolved = []
        for ev in considered:
            verdict, grade, reason = _effective(ev)
            if verdict == UNATTESTED:
                continue
            resolved.append((ev.anchor, verdict, grade, reason))

        if not resolved:
            reasons = [_effective(ev)[2] for ev in considered] or [
                "no evidence supplied for this subject"
            ]
            rows.append({
                "subject": subject, "verdict": UNATTESTED, "grade": F.UNKNOWN,
                "established_by": [], "reason": reasons[0],
            })
            unattested.append(subject)
            continue

        if any(v == MISMATCH for _, v, _, _ in resolved):
            final = MISMATCH
        elif any(v == INCONCLUSIVE for _, v, _, _ in resolved):
            final = INCONCLUSIVE
        else:
            final = MATCH

        # Independence is counted by separate matching acquisitions, not by distinct
        # anchor names: two out-of-band reads are two reads even though both are
        # 'oob_flash_read'. The strengthened grade uses the *penalised* grades from
        # _effective(), so a read-equivalence penalty survives to the subject verdict.
        match_items = [(a, g) for a, v, g, _ in resolved if v == MATCH]
        if match_items:
            top = max(_GRADE_RANK[g] for _, g in match_items)
            if len(match_items) >= 2 and top >= _GRADE_RANK[F.CORROBORATED]:
                best_grade = F.CONFIRMED
            else:
                best_grade = _RANK_GRADE[top]
        else:
            best_grade = F.UNKNOWN
        row = {
            "subject": subject,
            "verdict": final,
            "grade": best_grade,
            "established_by": sorted({a for a, _, _, _ in resolved}, key=anchor_rank),
            "reason": resolved[0][3],
        }
        rows.append(row)
        if final == MISMATCH:
            mismatched.append(subject)

    trustworthy = _trustworthy(rows)
    return {
        "rows": rows,
        "mismatched": mismatched,
        "unattested": unattested,
        "host_trustworthy": trustworthy,
        "statement": _statement(rows, trustworthy, mismatched),
    }


def _trustworthy(rows) -> bool:
    by_subject = {r["subject"]: r for r in rows}
    for subject, min_rank in REQUIRED_FOR_TRUST.items():
        row = by_subject[subject]
        if row["verdict"] != MATCH:
            return False
        if not row["established_by"]:
            return False
        if max(anchor_rank(a) for a in row["established_by"]) < min_rank:
            return False
    return True


def _statement(rows, trustworthy: bool, mismatched) -> str:
    if mismatched:
        return (
            "Firmware integrity is not established: "
            f"{', '.join(mismatched)} did not match the trusted reference. "
            "This is a positive finding of divergence, not an absence of evidence."
        )
    if trustworthy:
        return (
            "Firmware integrity is established for flash_image and crtm by anchors that "
            "do not ask the subject. This says the reference matched, not that the "
            "reference is correct, and it does not attest the operating system."
        )
    missing = [r["subject"] for r in rows
               if r["subject"] in REQUIRED_FOR_TRUST
               and (r["verdict"] != MATCH or not r["established_by"])]
    return (
        f"Firmware integrity is NOT established: {', '.join(missing)} unattested or "
        "inconclusive. No operating-system scan can supply this, so the answer is "
        "'unattested', not 'clean'."
    )


def os_scan_verdict(modules_seen: int = 0, modules_matching: int = 0) -> dict:
    """What an OS-side scan of firmware modules is worth.

    Always the same answer, whatever it found: nothing, about firmware. Provided as a
    callable so the refusal is explicit at the call site rather than a comment in a
    design document that nobody reads at 3am.
    """
    return {
        "verdict": UNATTESTED,
        "grade": F.UNKNOWN,
        "observations": {
            "modules_seen": modules_seen,
            "modules_matching": modules_matching,
        },
        "reason": (
            "OS-side scanning reads firmware through drivers the firmware can deceive; "
            "the result is a claim about the operating system, not about the firmware"
        ),
        "statement": (
            f"Scanned {modules_seen} modules through the operating system, "
            f"{modules_matching} matching expectations. This does not establish firmware "
            "trustworthiness and must not be reported as a firmware-clean result."
        ),
    }


def certify_host(assessment: dict, *, basis: str) -> dict:
    """Issue a host-trust claim, or refuse it.

    Called with the basis for the claim so an overclaim fails loudly at the boundary
    instead of turning into a sentence in a report.
    """
    rows = {r["subject"]: r for r in assessment["rows"]}
    weak = [
        subject for subject, min_rank in REQUIRED_FOR_TRUST.items()
        if not rows[subject]["established_by"]
        or max(anchor_rank(a) for a in rows[subject]["established_by"]) < min_rank
    ]
    if weak:
        raise IntegrityError(
            f"cannot certify the host on basis {basis!r}: {', '.join(weak)} was not "
            "established by an anchor independent of the subject. An OS scan cannot "
            "certify the hardware that hosts it."
        )
    if not assessment["host_trustworthy"]:
        raise IntegrityError(
            f"cannot certify the host on basis {basis!r}: the assessment does not "
            "support a trust verdict"
        )
    return {
        "certified": True,
        "basis": basis,
        "scope": sorted(REQUIRED_FOR_TRUST),
        "limits": [
            "certifies agreement with the trusted reference, not the correctness of it",
            "does not attest the operating system or any software above firmware",
            "in-circuit read-back equivalence remains unverified (H8)",
        ],
    }

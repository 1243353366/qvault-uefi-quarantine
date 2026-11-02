"""Where each implant actually lives, and what that changes.

Three implants, two substrates. LoJax and MoonBounce are DXE modules written into the platform
SPI flash device: they survive a disk wipe and an OS reinstall because they are not on the disk.
BlackLotus is not in hardware at all - it keeps files on the EFI System Partition and defeats
Secure Boot by chaining through a signed-but-vulnerable bootloader (CVE-2022-21894) after
enrolling its own Machine Owner Key.

That difference is not cosmetic. It changes what evidence counts (an out-of-band flash read
versus a boot-partition inventory), what remediation works (a reflash versus an ESP rebuild plus
revocation), and whether revocation is sufficient. The fingerprint catalogue used to print one
identical control table for all three, which quietly gave BlackLotus the SPI rows. Those rows
name a control that would not find it and an eradication step that would not remove it, so the
table is generated from this module instead.

Grades: the substrate of each family is documented in published analyses and is treated here as
CONFIRMED. What a given board does under reflash is board-specific and is not claimed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SPI_FLASH = "spi_flash"
ESP = "esp"
SUBSTRATES = (SPI_FLASH, ESP)

LOJAX = "lojax"
MOONBOUNCE = "moonbounce"
BLACKLOTUS = "blacklotus"


@dataclass(frozen=True)
class Residency:
    """One implant's substrate, and the consequences that follow from it."""

    family: str
    substrate: str
    location: str
    survives: tuple[str, ...]
    does_not_survive: tuple[str, ...]
    ground_truth: str
    not_ground_truth: str
    remediation: tuple[str, ...]
    revocation_removes: bool
    note: str = ""
    controls: tuple[dict, ...] = field(default_factory=tuple)

    @property
    def hardware_resident(self) -> bool:
        return self.substrate == SPI_FLASH


_SPI_CONTROLS = (
    {"mechanism": "firmware written from the running OS",
     "control": "BIOS write protection, flash-descriptor lockdown and SMM_BWP; the write itself "
                "is the event to alert on",
     "module": "containment, netpolicy"},
    {"mechanism": "implant persists across OS reinstall and disk wipe",
     "control": "out-of-band SPI read with an external programmer, diffed against the vendor "
                "image for this board and firmware version; never accept an OS scan as firmware "
                "evidence",
     "module": "firmware_integrity"},
    {"mechanism": "in-OS firmware readers are answered by the implant itself",
     "control": "treat chipsec and similar in-OS readers as a lead generator only; the SMM and "
                "SPI controller they query are inside the boundary under suspicion",
     "module": "firmware_integrity, separation"},
    {"mechanism": "revocation does not remove it",
     "control": "reflash is the eradication; a dbx update closes the boot path but leaves the "
                "module in place, so a read-back comparison is the closure criterion",
     "module": "containment, findings"},
    {"mechanism": "evidence of the compromise destroyed by the implant",
     "control": "seal evidence in the vault before analysis, so a hostile host cannot edit what "
                "was already captured",
     "module": "provenance, crypto, store"},
)

_ESP_CONTROLS = (
    {"mechanism": "files written to the boot partition, with no firmware write at all",
     "control": "integrity monitoring of the EFI System Partition against a known-good manifest, "
                "and a measured-boot log; the ESP write is the event to alert on",
     "module": "firmware_integrity, provenance"},
    {"mechanism": "implant survives an OS reinstall while the boot partition is preserved",
     "control": "reformat and recreate the ESP, then compare its contents against the vendor "
                "manifest; an OS reinstall that keeps the ESP is not remediation",
     "module": "findings, containment"},
    {"mechanism": "boot-chain trust bypassed through a signed-but-vulnerable bootloader "
                  "(CVE-2022-21894)",
     "control": "apply dbx/SVN revocation for the vulnerable bootloader and verify Secure Boot "
                "state instead of assuming it; here revocation is an effective control",
     "module": "firmware_integrity, pillars"},
    {"mechanism": "attacker-controlled key enrolled in the Machine Owner Key database",
     "control": "inventory MOK entries against an approved list, remove keys that were not "
                "enrolled from clean media, and keep the enrolment surface under change control",
     "module": "pillars, containment"},
    {"mechanism": "platform defences disabled by the bootkit",
     "control": "tamper protection with a management-side baseline; alert on local change",
     "module": "findings, pillars"},
    {"mechanism": "evidence of the compromise destroyed by the implant",
     "control": "seal evidence in the vault before analysis, so a hostile host cannot edit what "
                "was already captured",
     "module": "provenance, crypto, store"},
)

RESIDENCY: dict[str, Residency] = {
    LOJAX: Residency(
        family=LOJAX,
        substrate=SPI_FLASH,
        location="a DXE module inside the UEFI firmware volume in the platform SPI flash device",
        survives=("os_reinstall", "disk_wipe", "esp_reformat", "bootloader_update"),
        does_not_survive=("external reflash with a vendor image", "board replacement"),
        ground_truth="an external SPI programmer reading the flash device directly, diffed "
                     "against the vendor image for that exact board and firmware version",
        not_ground_truth="an in-OS firmware reader such as chipsec, which the implant's own "
                         "SMM or SPI controller can answer",
        remediation=("external reflash with a vendor image from a programmer",
                     "read-back comparison against the vendor image before returning to service",
                     "rotated credentials for anything the host held while infected"),
        revocation_removes=False,
        note="LoJax is built on a legitimate anti-theft agent; the benign reading has to be "
             "excluded before any finding.",
        controls=_SPI_CONTROLS,
    ),
    MOONBOUNCE: Residency(
        family=MOONBOUNCE,
        substrate=SPI_FLASH,
        location="modules injected into the SPI flash firmware, including its NVRAM area",
        survives=("os_reinstall", "disk_wipe", "esp_reformat", "bootloader_update"),
        does_not_survive=("external reflash with a vendor image", "board replacement"),
        ground_truth="an external SPI programmer reading the flash device directly, diffed "
                     "against the vendor image for that exact board and firmware version",
        not_ground_truth="an in-OS firmware reader, or the firmware's own self-report",
        remediation=("external reflash with a vendor image from a programmer",
                     "NVRAM considered separately, since the implant used it for storage",
                     "read-back comparison against the vendor image before returning to service"),
        revocation_removes=False,
        note="A user-mode component plus a firmware component: erasing the user-mode half proves "
             "nothing about the flash half.",
        controls=_SPI_CONTROLS,
    ),
    BLACKLOTUS: Residency(
        family=BLACKLOTUS,
        substrate=ESP,
        location="files on the EFI System Partition, plus MOK enrolment and boot configuration; "
                 "no SPI flash write",
        survives=("os_reinstall_preserving_esp",),
        does_not_survive=("esp_reformat", "full_disk_wipe", "dbx/SVN revocation of the "
                          "vulnerable bootloader"),
        ground_truth="the ESP mounted read-only from a trusted acquisition environment and hashed "
                     "against the vendor manifest, plus MOK, dbx/SVN and Secure Boot state, plus "
                     "the measured-boot log",
        not_ground_truth="an OS-side scan of the boot volume, or Secure Boot reporting itself "
                         "healthy after the bypass",
        remediation=("reformat and recreate the ESP",
                     "apply dbx/SVN revocation for the vulnerable bootloader",
                     "remove MOK entries that were not enrolled from clean media",
                     "verify Secure Boot state and a clean measured boot before returning to "
                     "service"),
        revocation_removes=True,
        note="Not hardware-resident. An SPI read finds nothing here, and an OS reinstall that "
             "keeps the ESP preserves it.",
        controls=_ESP_CONTROLS,
    ),
}


def get(family: str) -> Residency:
    if family not in RESIDENCY:
        raise ValueError(f"unknown family {family!r}")
    return RESIDENCY[family]


def controls(family: str) -> list[dict]:
    """The defensive inversion for this family, derived from its substrate."""
    return [dict(row) for row in get(family).controls]


def summary_rows() -> list[dict]:
    """One row per family, for the report table."""
    return [
        {
            "family": r.family,
            "substrate": "SPI flash" if r.substrate == SPI_FLASH else "EFI System Partition",
            "hardware": "yes" if r.hardware_resident else "no",
            "survives": ", ".join(s.replace("_", " ") for s in r.survives),
            "removed_by": "; ".join(r.remediation[:2]),
            "revocation": "sufficient with ESP rebuild" if r.revocation_removes
                          else "not sufficient on its own",
        }
        for r in RESIDENCY.values()
    ]


# --- the claim, checked -------------------------------------------------------------------

_SPI_RESIDENCY = re.compile(
    r"\b(spi\b[^.]{0,80}\b(persist|lives?|resid\w*|survives?|stored|sits?)\b"
    r"|\b(persist\w*|lives?|resid\w*|survives?|stored|sits?)\b[^.]{0,60}\b(spi\b|spi (flash|chip)|"
    r"flash chip|firmware (flash )?chip|hardware)\b)", re.IGNORECASE)


_NEGATIONS = ("not hardware-resident", "not hardware resident", "not in hardware",
              "isn't hardware-resident", "never hardware-resident", "no spi flash")


def _strip_negations(text: str) -> str:
    """A sentence that explicitly denies hardware residency is the claim we want made."""
    low = text
    for phrase in _NEGATIONS:
        low = low.replace(phrase, "")
    return low


def conflation_claims(text: str) -> list[str]:
    """Sentences that place a non-SPI family in firmware hardware.

    Only a residency claim counts: talking about hardware in the same sentence is fine, saying
    the implant lives there is not.
    """
    problems = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # a table row is one claim, not a paragraph: do not let adjacent cells blur together
        units = [stripped] if stripped.startswith("|") else re.split(r"(?<=[.!?])\s+", stripped)
        for unit in units:
            low = _strip_negations(unit.lower())
            for family in RESIDENCY:
                if family not in low:
                    continue
                if get(family).substrate != SPI_FLASH and _SPI_RESIDENCY.search(low):
                    problems.append(unit.strip()[:160])
    return problems


def assert_taxonomy() -> None:
    """Fail loudly if the catalogue and this table disagree."""
    known = set(RESIDENCY)
    if len(known) != len(RESIDENCY):
        raise AssertionError("duplicate family in RESIDENCY")
    for family, r in RESIDENCY.items():
        if r.substrate not in SUBSTRATES:
            raise AssertionError(f"{family}: unknown substrate {r.substrate!r}")
        if r.hardware_resident != (r.substrate == SPI_FLASH):
            raise AssertionError(f"{family}: hardware_resident disagrees with substrate")
        if not r.ground_truth or not r.not_ground_truth:
            raise AssertionError(f"{family}: ground truth must name what is and is not evidence")
        if not r.controls:
            raise AssertionError(f"{family}: no controls")
        joined = " ".join(c["mechanism"] + " " + c["control"] for c in r.controls).lower()
        if r.substrate == ESP:
            if "spi read" in joined or "out-of-band spi" in joined:
                raise AssertionError(f"{family}: an ESP-resident implant cannot be found by an "
                                     f"SPI read")
            if "firmware written from the running os" in joined:
                raise AssertionError(f"{family}: no firmware write happens in this family")
            if not r.revocation_removes:
                raise AssertionError(f"{family}: revocation is effective for this substrate")
        else:
            if "out-of-band spi" not in joined:
                raise AssertionError(f"{family}: an SPI-resident implant needs an out-of-band "
                                     f"read as its ground truth")
            if r.revocation_removes:
                raise AssertionError(f"{family}: revocation does not remove a flash module")

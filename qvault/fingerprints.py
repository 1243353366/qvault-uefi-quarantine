"""Published-source fingerprints for LoJax, MoonBounce and BlackLotus.

No sample of any of these families was handled to produce this file. Everything here
comes from published analysis, so every entry carries its source and an honest grade,
and a string match alone can never exceed INFERRED: strings appear in research papers,
in EDR rules, and in the comments of people reading both. A match is a lead that needs
corroboration, never an identification.

Each entry also carries the benign explanation that most often produces it. The LoJax
one is the important example: `rpcnetp` is also the legitimate Absolute/Computrace
anti-theft agent, factory-installed by several OEMs, so its presence is normal on a
great many machines.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import findings as F
from . import fwdiff as W

LOJAX = "lojax"
MOONBOUNCE = "moonbounce"
BLACKLOTUS = "blacklotus"
FAMILIES = (LOJAX, MOONBOUNCE, BLACKLOTUS)

SRC_LOJAX = "ESET, 'LoJax: First UEFI rootkit found in the wild, courtesy of the Sednit group' (2018)"
SRC_MOON = "Kaspersky GReAT, 'MoonBounce: the dark side of UEFI firmware' (2022)"
SRC_BLACKLOTUS = "ESET, 'BlackLotus UEFI bootkit: Myth confirmed' (2023)"
SRC_CVE = "Microsoft MSRC, CVE-2022-21894 Secure Boot security feature bypass"
SRC_NSA = "NSA/CISA BlackLotus remediation guidance (2023)"

#: A textual match is a lead. It is never better than this on its own.
MAX_TEXT_GRADE = F.INFERRED


@dataclass(frozen=True)
class Fingerprint:
    id: str
    family: str
    kind: str            # string | artifact | registry | structure | config
    value: str
    grade: str
    source: str
    benign: str          # the ordinary thing that produces this artefact
    hostile_when: str    # the corroboration that turns a lead into a finding
    countermeasure: str  # the defensive inversion of the mechanism
    note: str = ""


FINGERPRINTS: tuple[Fingerprint, ...] = (
    # ---- LoJax: firmware implant dropping a Windows-level persistence agent ----
    Fingerprint(
        "LOJAX-1", LOJAX, "artifact", "rpcnetp.exe", F.CORROBORATED, SRC_LOJAX,
        "Absolute/Computrace anti-theft agent, legitimately factory-installed by several OEMs",
        "rpcnetp present while the OEM's Computrace option is disabled or the licence is inactive",
        "Application allowlisting plus OEM confirmation that the Computrace agent is provisioned; "
        "detection alone is not actionable because the binary is often legitimate",
        "The canonical false positive of this family: presence is not compromise.",
    ),
    Fingerprint(
        "LOJAX-2", LOJAX, "registry", "Services/Rpcnetp", F.CORROBORATED, SRC_LOJAX,
        "the same anti-theft agent, installed by its vendor installer",
        "service re-created shortly after removal, or created with a binary outside the vendor path",
        "Monitor service creation for this name; treat re-creation after removal as the signal",
    ),
    Fingerprint(
        "LOJAX-3", LOJAX, "structure", "module-absent-from-vendor-image", F.INFERRED, SRC_LOJAX,
        "a legitimate OEM firmware update that post-dates the reference image",
        "the vendor confirms no such module, and the module's PE has no vendor signature",
        "Out-of-band SPI read compared against a vendor-published reference, not an OS scan",
        "Requires a trusted reference image; that dependency is the weak link, not the comparison.",
    ),
    # ---- MoonBounce: patched DXE driver carrying appended code ----
    Fingerprint(
        "MOON-1", MOONBOUNCE, "structure", "unnamed-pe-section", F.CORROBORATED, SRC_MOON,
        "some legitimate DXE drivers ship sections with blank names",
        "an unnamed section in CORE_DXE, or any module whose unnamed section is executable",
        "Compare every DXE module against the vendor reference; an unnamed section that is "
        "new relative to the reference justifies re-imaging the SPI flash from a known-good dump",
        "fwdiff already reports unnamed sections; this entry assigns meaning and a response.",
    ),
    Fingerprint(
        "MOON-2", MOONBOUNCE, "structure", "entry-point-outside-sections", F.INFERRED, SRC_MOON,
        "a packing or obfuscation tool, or a malformed image that will not boot",
        "combined with an unnamed executable section and a boot that still succeeds",
        "Re-image the firmware; a module whose entry point is not in any section cannot be trusted "
        "to be the module the vendor published",
    ),
    Fingerprint(
        "MOON-3", MOONBOUNCE, "structure", "code-appended-after-last-section", F.INFERRED, SRC_MOON,
        "padding or alignment bytes written by a flashing tool",
        "appended bytes that disassemble as code and are reachable from a patched prologue",
        "Boot Guard or an equivalent hardware-anchored verification of the first stage, so a "
        "patched driver is refused at boot rather than observed afterwards",
    ),
    # ---- BlackLotus: bootkit that disables the platform's own defences ----
    Fingerprint(
        "BL-1", BLACKLOTUS, "config", "hvci-disabled", F.CORROBORATED, SRC_BLACKLOTUS,
        "an administrator disabling memory integrity for driver compatibility, or a VM",
        "HVCI off together with Defender off and BitLocker suspended on the same host",
        "Re-enable HVCI; audit who changed it. The combination is the finding, not any one setting",
    ),
    Fingerprint(
        "BL-2", BLACKLOTUS, "config", "defender-disabled", F.CORROBORATED, SRC_BLACKLOTUS,
        "a third-party AV product that takes over, or an enterprise policy",
        "tamper protection disabled by something other than the management tool",
        "Tamper protection plus a management-side baseline; a local change should be an alert",
    ),
    Fingerprint(
        "BL-3", BLACKLOTUS, "config", "bitlocker-suspended", F.CORROBORATED, SRC_BLACKLOTUS,
        "a firmware update or an OS upgrade that suspends protection by design",
        "suspended with no corresponding update event in the servicing log",
        "Alert on suspension without a matching servicing event; re-seal the TPM afterwards",
    ),
    Fingerprint(
        "BL-4", BLACKLOTUS, "config", "secure-boot-bypass-cve", F.CORROBORATED, SRC_CVE,
        "an unpatched machine that was never exploited",
        "a bootloader version known-vulnerable in use after the dbx update was available",
        "Apply the revocation list (dbx) update; verify Secure Boot state is on and dbx current "
        "rather than assuming it",
    ),
    Fingerprint(
        "BL-5", BLACKLOTUS, "structure", "unexpected-efi-certificate", F.INFERRED, SRC_NSA,
        "a legitimate custom key enrolment by the device owner",
        "a certificate in the firmware key store that no administrator can account for",
        "Inventory db/MokList against a known set; require physical presence for enrolment",
    ),
)


def by_family(family: str) -> tuple[Fingerprint, ...]:
    return tuple(f for f in FINGERPRINTS if f.family == family)


def scan_text(data: bytes, family: str | None = None) -> list[dict]:
    """Textual leads in a blob. Graded at most INFERRED, always with a benign reading."""
    hay = data.lower()
    hits = []
    for fp in FINGERPRINTS:
        if fp.kind not in ("string", "artifact", "registry"):
            continue
        if family and fp.family != family:
            continue
        if fp.value.encode().lower() in hay:
            hits.append({
                "fingerprint": fp.id,
                "family": fp.family,
                "matched": fp.value,
                "grade": MAX_TEXT_GRADE if fp.grade == F.CONFIRMED else min(
                    (fp.grade, MAX_TEXT_GRADE), key=lambda g: F._RANK[g]),
                "benign": fp.benign,
                "hostile_when": fp.hostile_when,
                "countermeasure": fp.countermeasure,
                "source": fp.source,
            })
    return hits


def check_image(image: W.FirmwareImage) -> list[dict]:
    """Structural leads in a parsed firmware image."""
    out: list[dict] = []
    for guid, ffs in image.files.items():
        pe = ffs.pe
        if not pe:
            continue
        unnamed = [s for s in pe.sections if s.is_unnamed]
        if unnamed:
            fp = next(f for f in FINGERPRINTS if f.id == "MOON-1")
            out.append({
                "fingerprint": fp.id, "family": fp.family, "matched": f"{guid}:unnamed-section",
                "grade": fp.grade, "benign": fp.benign, "hostile_when": fp.hostile_when,
                "countermeasure": fp.countermeasure, "source": fp.source,
            })
        if pe.sections and not any(s.va <= pe.entry_rva < s.va + max(s.vsize, s.raw_size)
                                   for s in pe.sections):
            fp = next(f for f in FINGERPRINTS if f.id == "MOON-2")
            out.append({
                "fingerprint": fp.id, "family": fp.family,
                "matched": f"{guid}:entry-0x{pe.entry_rva:x}",
                "grade": fp.grade, "benign": fp.benign, "hostile_when": fp.hostile_when,
                "countermeasure": fp.countermeasure, "source": fp.source,
            })
    return out


def check_config(state: dict) -> list[dict]:
    """Windows security state. One disabled control is policy; three is a pattern."""
    out: list[dict] = []
    weakened = [k for k in ("hvci", "defender", "secure_boot")
                if state.get(k) is False]
    suspended = state.get("bitlocker_suspended") is True
    for fp in FINGERPRINTS:
        if fp.family != BLACKLOTUS or fp.kind != "config":
            continue
        key = {"BL-1": "hvci", "BL-2": "defender", "BL-3": "bitlocker_suspended",
               "BL-4": "secure_boot"}.get(fp.id)
        if not key:
            continue
        raised = state.get(key) is (False if key != "bitlocker_suspended" else True)
        if not raised:
            continue
        combo = len(weakened) >= 2 or (weakened and suspended)
        out.append({
            "fingerprint": fp.id, "family": fp.family, "matched": key,
            "grade": F.INFERRED if combo else F.HYPOTHESIS,
            "benign": fp.benign, "hostile_when": fp.hostile_when,
            "countermeasure": fp.countermeasure, "source": fp.source,
        })
    return out


def observations(hits: list[dict], gaps: tuple[str, ...] = ()) -> list[F.Observation]:
    """Leads as graded observations. Never findings: a human supplies the adjudication."""
    return [
        F.Observation(
            statement=f"{h['fingerprint']} ({h['family']}): matched {h['matched']}. "
                      f"Benign reading to exclude: {h['benign']}",
            plane="historical_record",
            grade=h["grade"],
            telemetry_gaps=tuple(gaps),
            source=h["source"],
        )
        for h in hits
    ]


def defender_inversion(family: str) -> list[dict]:
    """The opposite effect: for each mechanism, the control that defeats it.

    Derived from the family's substrate rather than written per family. The rows used to be
    identical for all three, which gave BlackLotus an SPI read and a reflash - a control that
    would not find it and an eradication step that would not remove it.
    """
    from . import residency as _residency

    if family not in FAMILIES:
        raise ValueError(f"unknown family {family!r}")
    return _residency.controls(family)


def assert_catalogue_integrity() -> None:
    """Every entry must carry a source, a benign reading and a countermeasure."""
    ids = set()
    for fp in FINGERPRINTS:
        if fp.id in ids:
            raise ValueError(f"duplicate fingerprint id {fp.id}")
        ids.add(fp.id)
        if fp.family not in FAMILIES:
            raise ValueError(f"{fp.id}: unknown family {fp.family}")
        if fp.grade not in F.GRADES:
            raise ValueError(f"{fp.id}: grade {fp.grade} outside the vocabulary")
        if fp.grade == F.CONFIRMED:
            raise ValueError(
                f"{fp.id}: CONFIRMED is unavailable here; no sample was handled, so no "
                "fingerprint in this file can be primary-sourced"
            )
        for field_name in ("source", "benign", "hostile_when", "countermeasure"):
            if not getattr(fp, field_name).strip():
                raise ValueError(f"{fp.id}: missing {field_name}")

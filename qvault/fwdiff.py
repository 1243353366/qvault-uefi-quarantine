"""
qvault.fwdiff
=============

Module-level firmware comparison, for the enclave side of the vault.

Why this exists
---------------
LoJax is catchable by inventory: it *adds* a file (`SecDxe`) and *removes* one
(`NtfsDxe`), so a file list diff finds it. MoonBounce is not: it patches an
existing, legitimate `CORE_DXE`, appends an **unnamed section** after `.reloc`,
and replaces five bytes at the start of three boot services with a `call`. The
file GUID, name, type and volume layout are unchanged.

The only reliable detection is therefore:

  1. inventory every FFS file by GUID, then
  2. hash every PE section inside every module, then
  3. compare both against the OEM image for that exact model/version.

This module does exactly that and nothing else. It parses; it never executes,
never decompresses, never maps a PE, and never follows a pointer it has not
bounds-checked. Parsing hostile firmware is inherently dangerous, which is why
this belongs in the analysis enclave, on a decrypted copy, and not at the vault
boundary (compare `qvault.triage`, which is the deliberately shallow boundary
triage).

Known limits
------------
* Compressed sections (EFI/Tiano/LZMA) are hashed as opaque bytes. A patch inside
  a compressed section shows up as "file changed" but not as a section diff.
* TE images are detected but not section-parsed.
* Section-level diffing cannot tell you *which function* changed without symbols
  or disassembly. It tells you *that* a module changed, and where to look.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Iterable

FV_SIG = b"_FVH"
FV_SIG_OFF = 0x28
MAX_FILES = 4096
MAX_SECTIONS = 96
MAX_PE_CANDIDATES = 4

# EFI_FV_FILETYPE_*
FFS_PAD = 0xF0
FFS_RAW = 0x01
TYPE_NAMES = {
    0x01: "RAW",
    0x02: "FREEFORM",
    0x03: "SECURITY_CORE",
    0x04: "PEI_CORE",
    0x05: "DXE_CORE",
    0x06: "PEIM",
    0x07: "DRIVER",
    0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION",
    0x0A: "SMM",
    0x0B: "FV_IMAGE",
    0x0C: "COMBINED_SMM_DXE",
    0x0D: "SMM_CORE",
    0x0E: "MM_STANDALONE",
    0x0F: "MM_CORE_STANDALONE",
    0xF0: "PAD",
}

SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_WRITE = 0x80000000

# ---------------------------------------------------------------------------
# Signature set derived from the MoonBounce reconstruction (report §3.9).
# These are detection indicators, not capabilities.
# ---------------------------------------------------------------------------

# Original prologues the implant replaces with E8 <rel32>.
IMPLANTED_PROLOGUES = {
    "AllocatePool": bytes.fromhex("48895c2408"),
    "CreateEventEx": bytes.fromhex("488bc44889"),
    "ExitBootServices": bytes.fromhex("48895c2408"),
}

# Immediates that appear in the shellcode stages.
IMMEDIATE_SIGNATURES = {
    "ExAllocatePool_prologue_check_0x6F4EB841": 0x6F4EB841,
    "hash_ExRegisterCallback_0x42790710": 0x42790710,
    "hash_ExAllocatePool_0x2802057D": 0x2802057D,
    "hash_MmMapIoSpace_0x1C88047D": 0x1C88047D,
    "ror13_ExAllocatePool_0x0311B83F": 0x0311B83F,
    "ror13_RtlInitAnsiString_0x41EBE619": 0x41EBE619,
    "ror13_RtlAnsiStringToUnicodeString_0x1C4F5B64": 0x1C4F5B64,
    "ror13_MmGetSystemRoutineAddress_0x0ADC68C7": 0x0ADC68C7,
}

# gEfiEventLegacyBootGuid {2A571201-4966-47F6-8B86-F31E41F32F10}, mixed-endian.
LEGACY_BOOT_GUID = bytes.fromhex("0112572a6649f6478b86f31e41f32f10")


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _align(n: int, a: int = 8) -> int:
    return (n + a - 1) & ~(a - 1)


@dataclass
class PeSection:
    name: str
    va: int
    vsize: int
    raw_size: int
    characteristics: int
    sha256: str
    raw_ptr: int

    @property
    def is_unnamed(self) -> bool:
        return not self.name.strip("\x00 ")

    @property
    def is_wx(self) -> bool:
        return bool(
            self.characteristics & SCN_MEM_EXECUTE
            and self.characteristics & SCN_MEM_WRITE
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name or "<unnamed>",
            "va": hex(self.va),
            "raw_size": self.raw_size,
            "sha256": self.sha256,
            "wx": self.is_wx,
        }


@dataclass
class PeImage:
    offset: int
    machine: int
    entry_rva: int
    entry_bytes: bytes
    sections: list[PeSection] = field(default_factory=list)


@dataclass
class FfsFile:
    guid: str
    ffs_type: int
    size: int
    offset: int
    sha256: str
    pe: PeImage | None = None

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.ffs_type, f"0x{self.ffs_type:02x}")

    def to_dict(self) -> dict:
        return {
            "guid": self.guid,
            "type": self.type_name,
            "size": self.size,
            "sha256": self.sha256,
            "sections": [s.to_dict() for s in (self.pe.sections if self.pe else [])],
        }


@dataclass
class FirmwareImage:
    name: str
    size: int
    volumes: int
    files: dict[str, FfsFile]
    data: bytes = b""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "size": self.size,
            "volumes": self.volumes,
            "files": len(self.files),
        }


def _guid_str(b: bytes) -> str:
    """Format 16 bytes as an EFI GUID with the first three fields little-endian."""
    d1 = int.from_bytes(b[0:4], "little")
    d2 = int.from_bytes(b[4:6], "little")
    d3 = int.from_bytes(b[6:8], "little")
    d4 = b[8:10].hex()
    d5 = b[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


def _parse_pe(data: bytes, base: int) -> PeImage | None:
    """Parse a PE header at `base` with strict bounds checking."""
    try:
        if data[base : base + 2] != b"MZ" or base + 0x40 > len(data):
            return None
        e_lfanew = int.from_bytes(data[base + 0x3C : base + 0x40], "little")
        pe = base + e_lfanew
        if e_lfanew <= 0 or pe + 24 > len(data) or data[pe : pe + 4] != b"PE\0\0":
            return None
        nsec = int.from_bytes(data[pe + 6 : pe + 8], "little")
        opt_size = int.from_bytes(data[pe + 20 : pe + 22], "little")
        opt = pe + 24
        if opt + opt_size > len(data) or nsec > MAX_SECTIONS:
            return None
        magic = int.from_bytes(data[opt : opt + 2], "little")
        if magic == 0x20B:  # PE32+
            entry = int.from_bytes(data[opt + 0x10 : opt + 0x14], "little")
        elif magic == 0x10B:  # PE32
            entry = int.from_bytes(data[opt + 0x10 : opt + 0x14], "little")
        else:
            return None
        machine = int.from_bytes(data[pe + 4 : pe + 6], "little")

        sections: list[PeSection] = []
        sect = opt + opt_size
        for i in range(nsec):
            off = sect + i * 40
            if off + 40 > len(data):
                break
            raw_name = data[off : off + 8]
            name = raw_name.rstrip(b"\x00").decode("latin-1", "replace")
            vsize = int.from_bytes(data[off + 8 : off + 12], "little")
            va = int.from_bytes(data[off + 12 : off + 16], "little")
            raw_size = int.from_bytes(data[off + 16 : off + 20], "little")
            raw_ptr = int.from_bytes(data[off + 20 : off + 24], "little")
            chars = int.from_bytes(data[off + 36 : off + 40], "little")
            start = base + raw_ptr
            end = start + raw_size
            if start > len(data):
                continue
            blob = data[start : min(end, len(data))]
            sections.append(
                PeSection(
                    name=name,
                    va=va,
                    vsize=vsize,
                    raw_size=raw_size,
                    characteristics=chars,
                    sha256=_sha(blob),
                    raw_ptr=raw_ptr,
                )
            )

        entry_bytes = b""
        for s in sections:
            if s.va <= entry < s.va + max(s.vsize, s.raw_size) and s.raw_size:
                delta = entry - s.va
                start = base + s.raw_ptr + delta
                entry_bytes = data[start : start + 8]
                break

        return PeImage(
            offset=base,
            machine=machine,
            entry_rva=entry,
            entry_bytes=entry_bytes,
            sections=sections,
        )
    except (IndexError, ValueError):
        return None


def _find_pe(data: bytes, lo: int, hi: int) -> PeImage | None:
    """Locate a PE image inside [lo, hi), trying a bounded number of candidates."""
    tries = 0
    idx = data.find(b"MZ", lo, hi)
    while idx != -1 and tries < MAX_PE_CANDIDATES:
        if idx + 0x40 <= hi:
            pe = _parse_pe(data, idx)
            if pe is not None:
                return pe
        tries += 1
        idx = data.find(b"MZ", idx + 2, hi)
    return None


def parse_firmware(data: bytes, name: str = "image") -> FirmwareImage:
    """Enumerate FFS files (and their PE sections) in a firmware image.

    Malformed regions are skipped rather than raising: the caller's job is to
    report "could not parse", never to crash on hostile input.
    """
    files: dict[str, FfsFile] = {}
    volumes = 0

    pos = data.find(FV_SIG)
    while pos != -1 and len(files) < MAX_FILES:
        base = pos - FV_SIG_OFF
        if base < 0 or base + 0x38 > len(data):
            pos = data.find(FV_SIG, pos + 1)
            continue
        fv_len = int.from_bytes(data[base + 0x20 : base + 0x28], "little")
        hdr_len = int.from_bytes(data[base + 0x30 : base + 0x32], "little")
        if fv_len <= 0 or hdr_len < 0x38 or base + fv_len > len(data):
            pos = data.find(FV_SIG, pos + 1)
            continue
        volumes += 1
        fv_end = base + fv_len
        cur = _align(base + hdr_len)

        while cur + 24 <= fv_end and len(files) < MAX_FILES:
            hdr = data[cur : cur + 24]
            if hdr == b"\xff" * 24 or hdr == b"\x00" * 24:
                break
            guid = _guid_str(hdr[0:16])
            ffs_type = hdr[18]
            size = int.from_bytes(hdr[20:23], "little")
            header_len = 24
            if size == 0xFFFFFF and cur + 32 <= fv_end:
                size = int.from_bytes(data[cur + 24 : cur + 32], "little")
                header_len = 32
            if size < header_len or cur + size > fv_end:
                break
            body = data[cur + header_len : cur + size]
            if ffs_type != FFS_PAD:
                pe = None
                if ffs_type not in (FFS_RAW, 0x0B):
                    pe = _find_pe(data, cur + header_len, cur + size)
                files.setdefault(
                    guid,
                    FfsFile(
                        guid=guid,
                        ffs_type=ffs_type,
                        size=size,
                        offset=cur,
                        sha256=_sha(body),
                        pe=pe,
                    ),
                )
            cur = _align(cur + size)

        pos = data.find(FV_SIG, pos + 1)

    return FirmwareImage(name=name, size=len(data), volumes=volumes, files=files, data=data)


# ---------------------------------------------------------------------------
# Signature scanning
# ---------------------------------------------------------------------------


def scan_signatures(data: bytes, *, max_hits: int = 64) -> list[dict]:
    """Scan for the reconstruction-derived indicators. Returns hits, not verdicts."""
    hits: list[dict] = []

    for label, value in IMMEDIATE_SIGNATURES.items():
        needle = value.to_bytes(4, "little")
        start = 0
        while len(hits) < max_hits:
            idx = data.find(needle, start)
            if idx == -1:
                break
            hits.append({"kind": "immediate", "signature": label, "offset": hex(idx)})
            start = idx + 1

    idx = data.find(LEGACY_BOOT_GUID)
    if idx != -1:
        hits.append(
            {
                "kind": "guid",
                "signature": "gEfiEventLegacyBootGuid reference",
                "offset": hex(idx),
            }
        )

    idx = data.find(b"\x41\x55\x48\xcb")
    if idx != -1:
        hits.append(
            {
                "kind": "pattern",
                "signature": "push r13; retfq (OslArchTransferToKernel tail)",
                "offset": hex(idx),
                "note": "legitimate in winload.efi; suspicious if adjacent code is modified",
            }
        )
    return hits


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def diff_images(reference: FirmwareImage, suspect: FirmwareImage) -> dict:
    """Compare two firmware images module-by-module.

    Returns a report with a `severity` of "clean", "low", "medium" or "high".
    """
    rep: dict = {
        "reference": reference.to_dict(),
        "suspect": suspect.to_dict(),
        "modules_added": [],
        "modules_removed": [],
        "modules_changed": [],
        "anomalies": [],
        "severity": "clean",
    }

    ref_ids, sus_ids = set(reference.files), set(suspect.files)
    for g in sorted(sus_ids - ref_ids):
        f = suspect.files[g]
        rep["modules_added"].append({"guid": g, "type": f.type_name, "size": f.size})
    for g in sorted(ref_ids - sus_ids):
        f = reference.files[g]
        rep["modules_removed"].append({"guid": g, "type": f.type_name, "size": f.size})

    for g in sorted(ref_ids & sus_ids):
        a, b = reference.files[g], suspect.files[g]
        if a.sha256 == b.sha256:
            continue
        entry = {
            "guid": g,
            "type": b.type_name,
            "filesize_delta": b.size - a.size,
            "sections_added": [],
            "sections_removed": [],
            "sections_changed": [],
            "entry_prologue": None,
        }
        if a.pe and b.pe:
            asec = {s.name or "<unnamed>": s for s in a.pe.sections}
            bsec = {s.name or "<unnamed>": s for s in b.pe.sections}
            for name in sorted(set(bsec) - set(asec)):
                entry["sections_added"].append(bsec[name].to_dict())
            for name in sorted(set(asec) - set(bsec)):
                entry["sections_removed"].append(asec[name].to_dict())
            for name in sorted(set(asec) & set(bsec)):
                if asec[name].sha256 != bsec[name].sha256:
                    entry["sections_changed"].append(
                        {
                            "name": name,
                            "ref_sha256": asec[name].sha256,
                            "suspect_sha256": bsec[name].sha256,
                        }
                    )
            if a.pe.entry_bytes and b.pe.entry_bytes and a.pe.entry_bytes != b.pe.entry_bytes:
                entry["entry_prologue"] = {
                    "reference": a.pe.entry_bytes.hex(),
                    "suspect": b.pe.entry_bytes.hex(),
                }
        rep["modules_changed"].append(entry)

    # Structural anomalies worth flagging even in the reference image.
    # `AllocatePool` and `ExitBootServices` share identical prologue bytes, so a
    # single patched location can match more than one signature; collect labels
    # per location instead of emitting duplicate findings.
    prologue_hits: dict[tuple, dict] = {}
    for g, f in suspect.files.items():
        if not f.pe:
            continue
        for s in f.pe.sections:
            if s.is_unnamed:
                rep["anomalies"].append(
                    {"guid": g, "anomaly": "unnamed PE section", "name": s.to_dict()["name"]}
                )
            if s.is_wx:
                rep["anomalies"].append(
                    {"guid": g, "anomaly": "section is both writable and executable", "name": s.name}
                )
        # A prologue replaced by a call inside a module present in both images.
        ref = reference.files.get(g)
        if ref and ref.pe:
            for sig_label, original in IMPLANTED_PROLOGUES.items():
                hit = _prologue_replaced(reference, suspect, ref, f, original)
                if not hit:
                    continue
                key = (g, hit["section"], hit["offset_in_section"])
                if key in prologue_hits:
                    prologue_hits[key]["detail"]["pattern_matches"].append(sig_label)
                    continue
                detail = dict(hit)
                detail["pattern_matches"] = [sig_label]
                entry = {
                    "guid": g,
                    "anomaly": "prologue replaced by call (boot-service hook pattern)",
                    "detail": detail,
                }
                prologue_hits[key] = entry
                rep["anomalies"].append(entry)

    if rep["modules_added"] or rep["modules_removed"]:
        rep["severity"] = "high"
    elif rep["modules_changed"] or rep["anomalies"]:
        rep["severity"] = "medium"
    if any(e["sections_added"] for e in rep["modules_changed"]):
        rep["severity"] = "high"
    return rep


def _prologue_replaced(
    ref_img: FirmwareImage,
    sus_img: FirmwareImage,
    ref: FfsFile,
    sus: FfsFile,
    original: bytes,
    *,
    max_finds: int = 32,
) -> dict | None:
    """Detect a function whose known-good prologue has become a call/jump.

    Method: find each occurrence of the expected prologue bytes inside an
    executable section of the *reference* image, then look at the same byte
    offset in the same-named section of the *suspect* image. If the suspect has
    E8 (`call rel32`) or E9 (`jmp rel32`) there, the function head has been
    overwritten with a hook.

    This is positional: it survives relinking of other sections, but not a
    wholesale layout change, and it cannot name the function without symbols.
    That is the honest limit of a byte-level diff, and it is still enough to
    catch the MoonBounce pattern, which patches prologues in place.
    """
    if not ref.pe or not sus.pe or not ref_img.data or not sus_img.data:
        return None
    for rsec in ref.pe.sections:
        if not (rsec.characteristics & SCN_MEM_EXECUTE) or not rsec.raw_size:
            continue
        r_start = ref.pe.offset + rsec.raw_ptr
        r_blob = ref_img.data[r_start : r_start + rsec.raw_size]
        for ssec in sus.pe.sections:
            if ssec.name != rsec.name or not ssec.raw_size:
                continue
            s_start = sus.pe.offset + ssec.raw_ptr
            s_blob = sus_img.data[s_start : s_start + ssec.raw_size]
            hits = 0
            k = r_blob.find(original)
            while k != -1 and hits < max_finds:
                if k < len(s_blob) and s_blob[k] in (0xE8, 0xE9):
                    return {
                        "section": rsec.name,
                        "offset_in_section": hex(k),
                        "expected_prologue": original.hex(),
                        "found_instead": s_blob[k : k + 5].hex(),
                    }
                hits += 1
                k = r_blob.find(original, k + 1)
    return None


def diff_files(ref_path: str, sus_path: str) -> dict:
    with open(ref_path, "rb") as fh:
        ref_data = fh.read()
    with open(sus_path, "rb") as fh:
        sus_data = fh.read()
    ref = parse_firmware(ref_data, name=ref_path)
    sus = parse_firmware(sus_data, name=sus_path)
    rep = diff_images(ref, sus)
    rep["signatures_reference"] = scan_signatures(ref_data)
    rep["signatures_suspect"] = scan_signatures(sus_data)
    return rep


def main(argv: Iterable[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="qvault.fwdiff",
        description="Compare a suspect firmware image against an OEM reference image.",
    )
    p.add_argument("--reference", required=True, help="known-good OEM image")
    p.add_argument("--suspect", required=True, help="image under examination")
    p.add_argument("--json", action="store_true", help="emit JSON (default)")
    a = p.parse_args(list(argv) if argv is not None else None)
    rep = diff_files(a.reference, a.suspect)
    print(json.dumps(rep, indent=2, sort_keys=True))
    return 0 if rep["severity"] == "clean" else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

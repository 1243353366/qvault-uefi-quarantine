"""
qvault.triage
=============

Inert static identification.

This module answers one question and only one question: "what *kind* of bytes
is this?" It never parses a container deeply, never decompresses a section,
never resolves a GUID to code, and never maps anything executable. Every
operation here is a bounded read of a byte range plus integer comparisons.

Rationale: firmware images are hostile input. Decompressors (LZMA, Tiano, EFI
compression), PE loaders and FFS parsers have all had exploitable bugs. A
quarantine tier that *needs* a parser to classify evidence has already given
the attacker a parser to attack. So the vault classifies with:

  * magic numbers at fixed offsets,
  * the SPI flash descriptor signature and region table (fixed layout),
  * bounded ASCII/UTF-16 string extraction for known indicator tokens,
  * Shannon entropy per 4 KiB block (to flag compressed/encrypted regions).

State of the art it approximates: UEFITool/UEFI-firmware-parser and Binarly's
FwHunt rules do the deep work, but only inside the analysis enclave, on a
decrypted copy, never at the boundary.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field

# --- magic number table (offset, bytes, label) -----------------------------

MAGIC: list[tuple[int, bytes, str]] = [
    (0, b"MZ", "dos_mz_header"),
    (0, b"\x7fELF", "elf"),
    (0, b"\x0f\x0f\x0f\x0f", "uefi_te_image_or_ffs_scan"),
    (0, b"FVH ", "noop"),
    (0x10, b"\x5a\xa5\xf0\x0f", "intel_spi_flash_descriptor"),
    (0, b"PK\x03\x04", "zip_container"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"7z\xbc\xaf\x27\x1c", "7zip"),
    (0, b"Rar!\x1a\x07", "rar"),
    (0, b"MDMP", "windows_minidump"),
    (0, b"L\0\0\0", "maybe_evtx_or_binary"),
]

# Firmware volume signature sits at offset 0x28 of the FV header, but images
# are frequently extracted at a non-zero base, so we also scan a bounded window.
FV_SIG = b"_FVH"

# Tokens that appear in the three families covered by the report, plus generic
# firmware-implant strings. Presence is a *signal*, never a verdict: several of
# these strings exist in clean vendor firmware.
DEFAULT_IOC_TOKENS = [
    "SecDxe",           # LoJax malicious DXE driver file name
    "autoche",          # LoJax BootExecute hijack binary
    "rpcnetp",          # LoJax / Computrace small agent
    "mboard.dll",       # MoonBounce second stage
    "glbaitech",        # MoonBounce C2 domain fragment
    "grubx64.efi",      # BlackLotus self-signed bootkit payload name
    "hpb_gate.php",     # BlackLotus C2 endpoint
    "MokList",          # BlackLotus MOK persistence variable
    "mcupdate_",        # abused by baton-drop style exploitation
    "When They Cry",    # BlackLotus self-signed CA subject
    "baton",            # exploitation tooling references
    "VbsPolicyDisable", # BlackLotus boot-time VBS kill switch
]

_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def shannon_entropy(block: bytes) -> float:
    if not block:
        return 0.0
    counts = Counter(block)
    n = len(block)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class TriageResult:
    size: int
    magic: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    ioc_hits: list[str] = field(default_factory=list)
    entropy_blocks: int = 0
    high_entropy_blocks: int = 0
    spi_regions: dict[str, int] | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "magic": self.magic,
            "ioc_hits": self.ioc_hits,
            "high_entropy_ratio": round(
                self.high_entropy_blocks / self.entropy_blocks, 3
            )
            if self.entropy_blocks
            else 0.0,
            "spi_regions": self.spi_regions,
            "notes": self.notes,
        }


def _parse_spi_descriptor(data: bytes) -> dict[str, int] | None:
    """Decode the Intel flash descriptor region table (FRBA..) if present.

    Layout: 16-byte descriptor header, then up to 5 region entries of
    (base:12 bits, limit:12 bits) packed 4 bytes each at offsets 0x54..0x63.
    FLMAP0 (offset 0x14) holds FRBA in bits 16..23, in units of 0x10 bytes.
    """
    if len(data) < 0x64:
        return None
    if data[0x10:0x14] != b"\x5a\xa5\xf0\x0f":
        return None
    flmap0 = int.from_bytes(data[0x14:0x18], "little")
    frba = ((flmap0 >> 16) & 0xFF) << 4
    if frba + 0x10 > len(data):
        return None
    names = ["bios", "me", "gbe", "platform_data", "dev_expansion"]
    regions: dict[str, int] = {}
    for i in range(5):
        off = frba + i * 4
        if off + 4 > len(data):
            break
        val = int.from_bytes(data[off : off + 4], "little")
        base_raw = val & 0x0FFF
        limit_raw = (val >> 16) & 0x0FFF
        # 0x000/0x000 marks an unused region; 0xFFF base is invalid.
        if base_raw == 0x000 and limit_raw == 0x000:
            continue
        if base_raw == 0xFFF or limit_raw < base_raw:
            continue
        base = base_raw << 12
        size = (limit_raw + 1 - base_raw) << 12
        # A region must lie inside the image we were given. This is what stops
        # a synthetic or truncated image from producing phantom regions.
        if base >= len(data) or base + size > len(data) + 0x1000:
            continue
        regions[names[i]] = size
    return regions or None


def triage_bytes(
    data: bytes, *, ioc_tokens: list[str] | None = None, max_scan: int = 4 * 1024 * 1024
) -> TriageResult:
    """Classify a byte string without executing or deeply parsing it."""
    tokens = ioc_tokens if ioc_tokens is not None else DEFAULT_IOC_TOKENS
    res = TriageResult(size=len(data))

    for off, sig, label in MAGIC:
        if data[off : off + len(sig)] == sig and label != "noop":
            res.magic.append(f"{label}@0x{off:x}")

    # Bounded scan window keeps ingestion predictable and DoS-resistant.
    window = data[:max_scan]

    fv_positions = []
    idx = window.find(FV_SIG)
    while idx != -1 and len(fv_positions) < 64:
        fv_positions.append(idx - 0x28)  # FV header base
        idx = window.find(FV_SIG, idx + 1)
    if fv_positions:
        res.magic.append(f"uefi_firmware_volume_header x{len(fv_positions)}")

    if window[:2] == b"MZ":
        e_lfanew = int.from_bytes(window[0x3C:0x40], "little") if len(window) > 0x40 else 0
        if 0 < e_lfanew < len(window) - 4 and window[e_lfanew : e_lfanew + 4] == b"PE\0\0":
            res.magic.append("pe_coff_image")
            machine = int.from_bytes(window[e_lfanew + 4 : e_lfanew + 6], "little")
            res.notes.append(f"pe_machine=0x{machine:04x}")
    if window[:2] == b"\x0f\x0f":
        res.magic.append("possible_te_or_ffs_compression_marker")

    # Strings and IOC tokens (ASCII + UTF-16LE), bounded count.
    found: list[str] = []
    for m in _ASCII_RE.finditer(window):
        found.append(m.group().decode("ascii", "ignore"))
        if len(found) >= 5000:
            break
    for m in _UTF16_RE.finditer(window):
        found.append(m.group().decode("utf-16le", "ignore"))
        if len(found) >= 8000:
            break
    res.strings = found[:200]  # small, human-reviewable sample kept in metadata

    lowered = [s.lower() for s in found]
    for tok in tokens:
        t = tok.lower()
        if any(t in s for s in lowered):
            res.ioc_hits.append(tok)

    # Entropy profile: compressed/encrypted payload regions stand out.
    blk = 4096
    for i in range(0, min(len(data), max_scan), blk):
        res.entropy_blocks += 1
        if shannon_entropy(data[i : i + blk]) > 7.2:
            res.high_entropy_blocks += 1

    res.spi_regions = _parse_spi_descriptor(data)
    if res.spi_regions:
        res.magic.append("intel_flash_descriptor_with_regions")

    if not res.magic:
        res.notes.append("no recognised container magic; opaque blob")
    return res


def load_ioc_tokens(path: str) -> list[str]:
    with open(path) as fh:
        return list(json.load(fh))

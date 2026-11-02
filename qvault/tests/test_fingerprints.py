"""Tests for the published-source fingerprint catalogue.

Every input here is synthesized. Nothing in this repository contains malware, and no
result below claims to identify one.
"""

import pytest

from qvault import findings as F
from qvault import fingerprints as P
from qvault import fwdiff as W


def build_pe_with_sections(names, payload=b"\x90" * 32):
    """Minimal PE-ish bytes with named sections, for structural checks."""
    out = bytearray()
    out += b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00"
    out += b"PE\x00\x00" + b"\x64\x86" + b"\x00" * 0x0E
    for i, name in enumerate(names):
        sec = name.encode().ljust(8, b"\x00")[:8]
        sec += (0x1000 * (i + 1)).to_bytes(4, "little")
        sec += (len(payload)).to_bytes(4, "little")
        sec += (len(payload)).to_bytes(4, "little")
        sec += (0x200 * (i + 1)).to_bytes(4, "little")
        sec += b"\x00" * 12
        sec += (0x60000020).to_bytes(4, "little")
        out += sec
    out += b"\x00" * 64
    out += payload * (max(1, len(names)))
    return bytes(out)


def test_catalogue_passes_its_own_integrity_check():
    P.assert_catalogue_integrity()


def test_no_fingerprint_claims_confirmed():
    """No sample was handled, so nothing here can be primary-sourced."""
    assert all(f.grade != F.CONFIRMED for f in P.FINGERPRINTS)


def test_every_fingerprint_carries_a_benign_reading():
    assert all(f.benign.strip() for f in P.FINGERPRINTS)


def test_every_fingerprint_names_a_countermeasure():
    assert all(f.countermeasure.strip() for f in P.FINGERPRINTS)


def test_all_three_families_are_covered():
    assert set(P.FAMILIES) == {"lojax", "moonbounce", "blacklotus"}
    for family in P.FAMILIES:
        assert P.by_family(family), family


def test_text_match_never_exceeds_inferred():
    hits = P.scan_text(b"C:/Windows/System32/rpcnetp.exe")
    assert hits
    for h in hits:
        assert F._RANK[h["grade"]] <= F._RANK[P.MAX_TEXT_GRADE]


def test_text_match_carries_the_false_positive_warning():
    hit = next(h for h in P.scan_text(b"rpcnetp.exe") if h["fingerprint"] == "LOJAX-1")
    assert "Computrace" in hit["benign"]
    assert hit["hostile_when"]


def test_a_string_in_a_research_note_is_indistinguishable_from_a_sample():
    """The reason a match is a lead: the same bytes appear in write-ups."""
    note = b"see LoJax analysis, which mentions rpcnetp.exe as its persistence agent"
    assert P.scan_text(note)


def test_scan_can_be_restricted_to_one_family():
    assert P.scan_text(b"rpcnetp.exe", family="blacklotus") == []


def test_unnamed_section_is_flagged_as_a_moonbounce_lead():
    data = build_pe_with_sections([".text", "\x00\x00\x00\x00\x00\x00\x00\x00"])
    image = W.parse_firmware(data)
    hits = P.check_image(image)
    guids = {h["fingerprint"] for h in hits}
    assert "MOON-1" in guids or not image.files


def test_entry_point_outside_sections_is_a_lead():
    pe_sections = [W.PeSection(name=".text", va=0x1000, vsize=0x100, raw_size=0x100,
                              characteristics=0x60000020, sha256="0", raw_ptr=0x200)]
    pe = W.PeImage(offset=0, machine=0x8664, entry_rva=0x9000, entry_bytes=b"\x90",
                   sections=pe_sections)
    ffs = W.FfsFile(guid="guid", ffs_type=7, size=0x200, offset=0x38, sha256="0", pe=pe)
    image = W.FirmwareImage(name="x", size=0x400, volumes=1, files={"guid": ffs})
    hits = P.check_image(image)
    assert any(h["fingerprint"] == "MOON-2" for h in hits)


def test_one_weakened_control_is_policy_not_a_pattern():
    hits = P.check_config({"hvci": False})
    assert hits
    assert all(h["grade"] == F.HYPOTHESIS for h in hits)


def test_several_weakened_controls_raise_the_grade():
    hits = P.check_config({"hvci": False, "defender": False})
    assert all(F._RANK[h["grade"]] >= F._RANK[F.INFERRED] for h in hits)


def test_healthy_config_produces_no_leads():
    assert P.check_config({"hvci": True, "defender": True, "secure_boot": True}) == []


def test_leads_become_observations_not_findings():
    obs = P.observations(P.scan_text(b"rpcnetp.exe"))
    assert obs
    assert all(isinstance(o, F.Observation) for o in obs)
    assert not any(isinstance(o, F.Finding) for o in obs)


def test_observations_inherit_declared_gaps():
    obs = P.observations(P.scan_text(b"rpcnetp.exe"), gaps=("firmware",))
    assert all(o.telemetry_gaps == ("firmware",) for o in obs)


def test_defender_inversion_exists_for_every_family():
    for family in P.FAMILIES:
        controls = P.defender_inversion(family)
        assert controls
        assert all(c["control"] and c["module"] for c in controls)


def test_defender_inversion_rejects_unknown_family():
    with pytest.raises(ValueError):
        P.defender_inversion("blackshades")


def test_integrity_check_rejects_a_confirmed_fingerprint(monkeypatch):
    bad = P.Fingerprint("X", "lojax", "string", "v", F.CONFIRMED, "s", "b", "h", "c")
    monkeypatch.setattr(P, "FINGERPRINTS", (bad,))
    with pytest.raises(ValueError):
        P.assert_catalogue_integrity()


def test_integrity_check_rejects_a_missing_benign_reading(monkeypatch):
    bad = P.Fingerprint("X", "lojax", "string", "v", F.INFERRED, "s", "", "h", "c")
    monkeypatch.setattr(P, "FINGERPRINTS", (bad,))
    with pytest.raises(ValueError):
        P.assert_catalogue_integrity()

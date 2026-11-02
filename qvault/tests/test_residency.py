"""Three implants, two substrates, and the controls that follow from that.

The failure this pins: the generated control table was identical for all three families, so
BlackLotus was given an out-of-band SPI read (which cannot find it) and a reflash (which would
not remove it). A clean SPI read on an ESP-resident infection reads as exoneration.
"""
import pytest

from qvault import fingerprints as F
from qvault import residency as R


def test_every_catalogued_family_declares_a_substrate():
    for family in F.FAMILIES:
        assert R.get(family).substrate in R.SUBSTRATES


def test_the_taxonomy_is_internally_consistent():
    R.assert_taxonomy()


def test_hardware_residency_follows_from_the_substrate():
    assert R.get("lojax").hardware_resident is True
    assert R.get("moonbounce").hardware_resident is True
    assert R.get("blacklotus").hardware_resident is False


def test_blacklotus_lives_on_the_boot_partition_and_not_in_flash():
    blacklotus = R.get("blacklotus")
    assert blacklotus.substrate == R.ESP
    assert "EFI System Partition" in blacklotus.location
    assert "no SPI flash write" in blacklotus.location


def test_an_spi_read_is_never_offered_for_an_esp_resident_family():
    for family in ("blacklotus",):
        text = " ".join(c["mechanism"] + " " + c["control"] for c in R.controls(family)).lower()
        assert "spi read" not in text
        assert "out-of-band spi" not in text
        assert "firmware written from the running os" not in text


def test_an_spi_resident_family_requires_an_out_of_band_read():
    for family in ("lojax", "moonbounce"):
        text = " ".join(c["control"] for c in R.controls(family)).lower()
        assert "out-of-band spi" in text


def test_revocation_is_not_described_as_sufficient_for_a_flash_module():
    for family in ("lojax", "moonbounce"):
        record = R.get(family)
        assert record.revocation_removes is False
        assert any("reflash" in step for step in record.remediation)


def test_revocation_is_part_of_the_fix_for_the_bootloader_case():
    blacklotus = R.get("blacklotus")
    assert blacklotus.revocation_removes is True
    assert any("dbx" in step for step in blacklotus.remediation)


def test_eradication_and_evidence_are_named_per_substrate():
    for family, record in R.RESIDENCY.items():
        assert record.ground_truth
        assert record.not_ground_truth
        assert record.remediation
        assert record.ground_truth != record.not_ground_truth, family


def test_a_flash_module_is_not_removed_by_a_boot_partition_rebuild():
    for family in ("lojax", "moonbounce"):
        assert not any("esp" in s.lower() for s in R.get(family).remediation)


@pytest.mark.parametrize("sentence", [
    "BlackLotus persists in SPI flash and survives a disk wipe.",
    "The BlackLotus implant lives in the firmware flash chip.",
    "BlackLotus resides in hardware, below the operating system.",
])
def test_the_reader_flags_an_esp_implant_placed_in_flash(sentence):
    assert R.conflation_claims(sentence)


@pytest.mark.parametrize("sentence", [
    "BlackLotus is not hardware-resident: an SPI read finds nothing.",
    "LoJax persists in SPI flash and survives a disk wipe.",
    "BlackLotus keeps files on the EFI System Partition.",
    "The analyst used an SPI programmer and discussed hardware write protection.",
])
def test_correct_statements_are_not_flagged(sentence):
    assert R.conflation_claims(sentence) == []


def test_the_generated_table_matches_the_taxonomy():
    rows = R.summary_rows()
    assert {r["family"] for r in rows} == set(R.RESIDENCY)
    blacklotus = next(r for r in rows if r["family"] == "blacklotus")
    assert blacklotus["hardware"] == "no"
    assert "SPI" not in blacklotus["substrate"]


def test_the_control_table_is_derived_not_copied():
    """Different substrates must not produce identical control rows."""
    lojax = [c["mechanism"] for c in R.controls("lojax")]
    blacklotus = [c["mechanism"] for c in R.controls("blacklotus")]
    assert lojax != blacklotus

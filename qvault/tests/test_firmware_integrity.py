"""Tests for qvault.firmware_integrity — the OS may not certify its own host."""

from __future__ import annotations

import pytest

from qvault import findings as F
from qvault import firmware_integrity as W
from qvault.firmware_integrity import FirmwareEvidence, IntegrityError


def oob(subject=W.FLASH_IMAGE, verdict=W.MATCH, **kw) -> FirmwareEvidence:
    return FirmwareEvidence("oob_flash_read", subject, verdict, **kw)


def good_host() -> list[FirmwareEvidence]:
    return [oob(W.FLASH_IMAGE), oob(W.CRTM)]


# --- the central refusal -------------------------------------------------


def test_os_mediated_anchor_establishes_nothing():
    assert W.ANCHORS["os_mediated"].establishes == frozenset()
    assert W.admits("os_mediated") is False
    for subject in W.SUBJECTS:
        assert subject not in W.ANCHORS["os_mediated"].establishes


def test_os_scan_cannot_make_a_subject_attested():
    ev = [FirmwareEvidence("os_mediated", W.FLASH_IMAGE, W.MATCH)]
    a = W.assess(ev)
    assert W.FLASH_IMAGE in a["unattested"]
    assert a["host_trustworthy"] is False


def test_os_scan_verdict_is_the_same_whatever_it_found():
    empty = W.os_scan_verdict(0, 0)
    perfect = W.os_scan_verdict(212, 212)
    assert empty["verdict"] == perfect["verdict"] == W.UNATTESTED
    assert empty["grade"] == perfect["grade"] == F.UNKNOWN
    assert "must not be reported as a firmware-clean result" in perfect["statement"]


def test_certify_host_refuses_an_os_scan_basis():
    a = W.assess([FirmwareEvidence("os_mediated", W.FLASH_IMAGE, W.MATCH),
                  FirmwareEvidence("os_mediated", W.CRTM, W.MATCH)])
    with pytest.raises(IntegrityError) as e:
        W.certify_host(a, basis="os_scan")
    assert "cannot certify the hardware that hosts it" in str(e.value)


# --- what each anchor can and cannot do ----------------------------------


def test_tpm_quote_attests_the_boot_chain_but_not_flash_or_crtm():
    ev = [FirmwareEvidence("tpm_quote", W.BOOT_CHAIN, W.MATCH)]
    a = W.assess(ev)
    rows = {r["subject"]: r for r in a["rows"]}
    assert rows[W.BOOT_CHAIN]["verdict"] == W.MATCH
    assert rows[W.FLASH_IMAGE]["verdict"] == W.UNATTESTED
    assert rows[W.CRTM]["verdict"] == W.UNATTESTED
    assert a["host_trustworthy"] is False


def test_a_clean_tpm_quote_alone_is_not_host_trust():
    a = W.assess([FirmwareEvidence("tpm_quote", W.BOOT_CHAIN, W.MATCH)])
    assert a["host_trustworthy"] is False
    assert "NOT established" in a["statement"]
    with pytest.raises(IntegrityError):
        W.certify_host(a, basis="tpm_quote_only")


def test_pre_os_measurement_is_only_a_hypothesis():
    a = W.assess([FirmwareEvidence("pre_os_measured", W.BOOT_CHAIN, W.MATCH)])
    row = {r["subject"]: r for r in a["rows"]}[W.BOOT_CHAIN]
    assert row["grade"] == F.HYPOTHESIS


def test_out_of_band_read_establishes_flash_and_crtm():
    a = W.assess(good_host())
    assert a["host_trustworthy"] is True
    cert = W.certify_host(a, basis="oob_flash_read")
    assert cert["certified"] is True
    assert "does not attest the operating system" in " ".join(cert["limits"])


def test_hardware_boot_rom_can_substitute_for_crtm_only():
    ev = [oob(W.FLASH_IMAGE), FirmwareEvidence("hardware_boot_rom", W.CRTM, W.MATCH)]
    a = W.assess(ev)
    assert a["host_trustworthy"] is True

    ev = [FirmwareEvidence("hardware_boot_rom", W.CRTM, W.MATCH)]  # no flash evidence
    assert W.assess(ev)["host_trustworthy"] is False


# --- reference and read-equivalence caveats ------------------------------


def test_untrusted_reference_makes_a_match_inconclusive():
    a = W.assess([oob(W.FLASH_IMAGE, reference_trusted=False), oob(W.CRTM)])
    rows = {r["subject"]: r for r in a["rows"]}
    assert rows[W.FLASH_IMAGE]["verdict"] == W.INCONCLUSIVE
    assert a["host_trustworthy"] is False


def test_unverified_read_equivalence_lowers_the_grade():
    verified = W.assess([oob(W.FLASH_IMAGE, equivalence_verified=True), oob(W.CRTM)])
    unverified = W.assess([oob(W.FLASH_IMAGE, equivalence_verified=False), oob(W.CRTM)])
    gv = {r["subject"]: r["grade"] for r in verified["rows"]}[W.FLASH_IMAGE]
    gu = {r["subject"]: r["grade"] for r in unverified["rows"]}[W.FLASH_IMAGE]
    assert gv == F.CORROBORATED
    assert gu == F.INFERRED   # one step down for H8


def test_two_independent_anchors_confirm_a_subject():
    ev = [oob(W.FLASH_IMAGE), oob(W.FLASH_IMAGE), oob(W.CRTM)]
    row = {r["subject"]: r for r in W.assess(ev)["rows"]}[W.FLASH_IMAGE]
    assert row["grade"] == F.CONFIRMED


# --- disagreement --------------------------------------------------------


def test_any_mismatch_wins_over_agreeing_anchors():
    ev = [oob(W.FLASH_IMAGE, W.MATCH),
          FirmwareEvidence("hardware_boot_rom", W.CRTM, W.MATCH),
          FirmwareEvidence("tpm_quote", W.BOOT_CHAIN, W.MATCH),
          FirmwareEvidence("tpm_quote", W.DXE_DRIVERS, W.MISMATCH)]
    a = W.assess(ev)
    assert W.DXE_DRIVERS in a["mismatched"]
    assert "positive finding of divergence" in a["statement"]


def test_mismatch_in_a_required_subject_blocks_trust():
    a = W.assess([oob(W.FLASH_IMAGE, W.MISMATCH), oob(W.CRTM)])
    assert a["host_trustworthy"] is False
    with pytest.raises(IntegrityError):
        W.certify_host(a, basis="oob_flash_read")


# --- bookkeeping ---------------------------------------------------------


def test_ec_and_option_rom_are_tracked_but_not_required():
    a = W.assess(good_host())
    assert W.EC_ME in a["unattested"]
    assert a["host_trustworthy"] is True


def test_no_evidence_yields_nothing_attested():
    a = W.assess([])
    assert a["host_trustworthy"] is False
    assert set(a["unattested"]) == set(W.SUBJECTS)


def test_unknown_anchor_subject_or_verdict_is_rejected():
    with pytest.raises(IntegrityError):
        FirmwareEvidence("ouija", W.CRTM, W.MATCH)
    with pytest.raises(IntegrityError):
        FirmwareEvidence("oob_flash_read", "cpu_microcode", W.MATCH)
    with pytest.raises(IntegrityError):
        FirmwareEvidence("oob_flash_read", W.CRTM, "probably_fine")


def test_anchor_ranks_are_ordered_by_independence():
    order = ["os_mediated", "pre_os_measured", "tpm_quote", "hardware_boot_rom", "oob_flash_read"]
    ranks = [W.anchor_rank(a) for a in order]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


def test_required_trust_threshold_excludes_weak_anchors():
    for subject, min_rank in W.REQUIRED_FOR_TRUST.items():
        assert min_rank >= 3, subject
        assert W.anchor_rank("tpm_quote") < min_rank
        assert W.anchor_rank("os_mediated") < min_rank

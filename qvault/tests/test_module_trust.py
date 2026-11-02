"""The trust boundaries, as they appear in the modules that make the claims.

Each test here corresponds to a way a module could state something it has not established:
promoting a class by repeating it, claiming custody on a filesystem, or letting a refusal
reveal whether an object exists.
"""
import tempfile

import pytest

from qvault import findings as F
from qvault import firmware_integrity as FI
from qvault import retrieve as R
from qvault import separation as S
from qvault import store as St


# --- firmware_integrity: repetition is not a stronger class ---------------------------

def test_firmware_measuring_itself_twice_is_still_a_hypothesis():
    """The host trust gap in code: the subject cannot confirm its own firmware."""
    assert FI.grade_for("pre_os_measured") == F.HYPOTHESIS
    assert FI.grade_for("pre_os_measured", independent_sources=2) == F.HYPOTHESIS
    assert FI.grade_for("pre_os_measured", independent_sources=50) == F.HYPOTHESIS


@pytest.mark.parametrize("sources", [1, 2, 10])
def test_an_os_mediated_read_never_grades(sources):
    assert FI.grade_for("os_mediated", independent_sources=sources) == F.UNKNOWN


def test_out_of_band_reads_cap_at_corroborated_however_many():
    assert FI.grade_for("oob_flash_read", independent_sources=2) == F.CORROBORATED
    assert FI.grade_for("oob_flash_read", independent_sources=9) == F.CORROBORATED


def test_every_anchor_declares_an_evidence_class():
    for name in FI.ANCHORS:
        assert FI.evidence_class_for(name) in S.EVIDENCE_CLASSES


def test_an_unknown_anchor_is_refused_rather_than_graded():
    with pytest.raises(FI.IntegrityError):
        FI.evidence_class_for("vendor_says_fine")


def test_anchor_grade_never_exceeds_its_class_ceiling():
    for name in FI.ANCHORS:
        ceiling = S.grade_ceiling([FI.evidence_class_for(name)])
        graded = FI.grade_for(name, independent_sources=5)
        if ceiling is None:
            assert graded == F.UNKNOWN
        else:
            order = list(reversed(F.GRADES))
            assert order.index(graded) <= order.index(ceiling), name


# --- store: durability is declared, never guessed -------------------------------------

def test_a_fresh_vault_is_not_worm_and_says_so():
    paths = St.VaultPaths.open(tempfile.mkdtemp())
    assert St.storage_class(paths) == S.NOT_WORM
    summary = St.custody_summary(paths)
    assert summary["claim_supported"] is False
    assert "object-lock" in summary["reason"] or "rewrite" in summary["reason"]


def test_a_declared_worm_vault_supports_the_claim():
    paths = St.VaultPaths.open(tempfile.mkdtemp())
    St.declare_storage(paths, S.WORM)
    assert St.storage_class(paths) == S.WORM
    assert St.custody_summary(paths)["claim_supported"] is True
    assert St.assert_custody(paths)["supported"] is True


def test_an_unknown_storage_class_is_refused_not_assumed_durable():
    paths = St.VaultPaths.open(tempfile.mkdtemp())
    with pytest.raises(St.StoreError):
        St.declare_storage(paths, "probably_fine")


def test_custody_is_refused_on_a_local_vault():
    paths = St.VaultPaths.open(tempfile.mkdtemp())
    with pytest.raises(S.CustodyClaimError):
        St.assert_custody(paths)


# --- retrieve: a refusal must not reveal existence ------------------------------------

def _refusal(paths, object_id):
    with pytest.raises(R.AuthorizationError) as err:
        R.retrieve(paths, object_id, shares=[], threshold=1, requester="alice",
                   out_dir=tempfile.mkdtemp())
    return str(err.value)


def test_approvals_are_checked_before_the_envelope_is_read(monkeypatch):
    """Proves the ordering: touching the envelope first would leak existence."""
    paths = St.VaultPaths.open(tempfile.mkdtemp())

    def explode(*args, **kwargs):
        raise AssertionError("envelope was read before approvals were checked")

    monkeypatch.setattr(St, "get_envelope", explode)
    message = _refusal(paths, "a" * 64)
    assert "dual control" in message


def test_a_missing_object_and_an_unapproved_one_look_identical():
    paths = St.VaultPaths.open(tempfile.mkdtemp())
    missing = _refusal(paths, "b" * 64)
    also_missing = _refusal(paths, "c" * 64)
    assert missing == also_missing
    for leak in ("no such", "not found", "missing", "exists", "b" * 64):
        assert leak not in missing.lower()


# --- separation: only verification may certify ----------------------------------------

@pytest.mark.parametrize("component", ["vault_store", "engine_verifier", "firmware_verifier"])
def test_certification_actions_are_assigned_to_verification(component):
    role = S.role_of(component)
    if role == S.VERIFICATION:
        assert S.may(component, "certify_host")
    else:
        assert not S.may(component, "certify_host")


def test_the_store_cannot_certify_and_the_verifier_cannot_hold_custody():
    assert not S.may("vault_store", "certify_host")
    assert S.may("vault_store", "claim_custody")
    assert not S.may("firmware_verifier", "claim_custody")

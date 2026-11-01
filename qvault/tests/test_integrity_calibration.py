"""Tests for self-integrity, impersonation detection, and calibration."""

from __future__ import annotations

import os

import pytest

from qvault import calibration as K
from qvault import findings as F
from qvault import integrity as N


@pytest.fixture()
def tree(tmp_path):
    """A minimal installation tree."""
    root = tmp_path / "app"
    (root / "pkg").mkdir(parents=True)
    (root / "app.py").write_text("print('hi')\n")
    (root / "pkg" / "core.py").write_text("X = 1\n")
    (root / "pkg" / "__pycache__").mkdir()
    (root / "pkg" / "__pycache__" / "core.cpython-311.pyc").write_bytes(b"bytecode")
    return root


# --- manifest and verification -------------------------------------------


def test_manifest_digests_regular_files_and_skips_bytecode(tree):
    m = N.build_manifest(str(tree))
    assert set(m["files"]) == {"app.py", "pkg/core.py"}
    assert m["file_count"] == 2
    assert m["digest"].startswith("sha256:")


def test_manifest_digest_is_order_independent(tree):
    first = N.build_manifest(str(tree))["digest"]
    second = N.build_manifest(str(tree))["digest"]
    assert first == second


def test_matching_external_digest_verifies(tree):
    digest = N.build_manifest(str(tree))["digest"]
    out = N.verify_tree(str(tree), digest, provenance=N.OUT_OF_BAND_DIGEST)
    assert out["status"] == N.VERIFIED
    assert out["verified"] is True
    assert out["grade"] == F.CORROBORATED


def test_changed_file_breaks_the_digest(tree):
    digest = N.build_manifest(str(tree))["digest"]
    (tree / "pkg" / "core.py").write_text("X = 2  # trojan\n")
    out = N.verify_tree(str(tree), digest, provenance=N.OUT_OF_BAND_DIGEST)
    assert out["status"] == N.MISMATCH
    assert out["verified"] is False
    assert any("digest_mismatch" in g for g in out["gaps"])


def test_no_external_reference_is_unverified_not_verified(tree):
    out = N.verify_tree(str(tree), "", provenance=N.NONE)
    assert out["status"] == N.UNVERIFIED
    assert out["verified"] is False
    assert out["grade"] is None
    assert any("unverified_self_measurement" in g for g in out["gaps"])


def test_a_digest_stored_beside_the_code_is_refused(tree):
    digest = N.build_manifest(str(tree))["digest"]
    with pytest.raises(N.IntegrityError) as e:
        N.verify_tree(str(tree), digest, provenance=N.SELF_EMBEDDED)
    assert "lock whose key is taped to the door" in str(e.value) or "proves nothing" in str(e.value)


def test_unknown_provenance_is_rejected(tree):
    with pytest.raises(N.IntegrityError):
        N.verify_tree(str(tree), "sha256:x", provenance="trust_me")


def test_world_writable_code_is_reported(tree):
    os.chmod(tree / "app.py", 0o666)
    out = N.verify_tree(str(tree), "", provenance=N.NONE)
    assert "app.py" in out["world_writable"]
    assert any("world_writable" in g for g in out["gaps"])


# --- impersonation ------------------------------------------------------


def test_a_clean_tree_triggers_nothing_serious(tree):
    checks = N.impersonation_checks(str(tree))
    serious = [c for c in checks if c["present"] and c["severity"] in ("high", "medium")]
    assert serious == []


def test_startup_hook_inside_the_tree_is_high_severity(tree):
    (tree / "sitecustomize.py").write_text("import os\n")
    checks = {c["check"]: c for c in N.impersonation_checks(str(tree))}
    assert checks["startup_hook_in_tree"]["present"] is True
    assert checks["startup_hook_in_tree"]["severity"] == "high"


def test_unknown_path_position_is_an_unknown_not_a_finding(tree):
    """If we are not on sys.path, shadowing is unanswerable, not absent."""
    checks = {c["check"]: c for c in N.impersonation_checks(str(tree), sys_path=["/nowhere"])}
    assert checks["path_position_unknown"]["present"] is True
    assert checks["path_position_unknown"]["severity"] == "info"


def test_import_shadowing_is_detected(tree, tmp_path):
    shadow = tmp_path / "rogue"
    shadow.mkdir()
    (shadow / "qvault.py").write_text("# trojan\n")
    checks = {c["check"]: c for c in N.impersonation_checks(
        str(tree), sys_path=[str(shadow), str(tree)])}
    assert checks["import_shadowing"]["present"] is True


def test_ordinary_pycache_is_not_source_less_bytecode(tree):
    """Regression: the fixture has a normal __pycache__ beside real source."""
    checks = {c["check"]: c for c in N.impersonation_checks(str(tree))}
    assert checks["source_less_bytecode"]["present"] is False


def test_source_less_bytecode_is_detected(tree):
    (tree / "pkg" / "ghost.cpython-311.pyc").write_bytes(b"\x00")
    checks = {c["check"]: c for c in N.impersonation_checks(str(tree))}
    assert checks["source_less_bytecode"]["present"] is True


def test_every_check_carries_an_ordinary_explanation(tree):
    for check in N.impersonation_checks(str(tree)):
        assert check["usual_reason"], check["check"]


# --- self-scan ----------------------------------------------------------


def test_self_scan_of_a_verified_clean_tree_finds_nothing(tree):
    digest = N.build_manifest(str(tree))["digest"]
    out = N.self_scan(str(tree), digest, provenance=N.OUT_OF_BAND_DIGEST,
                      sys_path=[str(tree)])
    assert out["verdict"] == F.NO_EVIDENCE_FOUND
    assert out["integrity"]["verified"] is True


def test_self_scan_of_a_modified_tree_is_suspicious(tree):
    digest = N.build_manifest(str(tree))["digest"]
    (tree / "pkg" / "core.py").write_text("X = 2\n")
    out = N.self_scan(str(tree), digest, provenance=N.OUT_OF_BAND_DIGEST,
                      sys_path=[str(tree)])
    assert out["verdict"] == F.SUSPICIOUS_VERDICT
    assert out["integrity"]["status"] == N.MISMATCH


def test_self_scan_without_an_external_reference_is_inconclusive(tree):
    out = N.self_scan(str(tree), "", provenance=N.NONE, sys_path=[str(tree)])
    assert out["verdict"] == F.INCONCLUSIVE


def test_self_scan_never_returns_a_cleanliness_verdict(tree):
    for provenance in (N.NONE, N.OUT_OF_BAND_DIGEST):
        digest = N.build_manifest(str(tree))["digest"] if provenance else ""
        out = N.self_scan(str(tree), digest, provenance=provenance, sys_path=[str(tree)])
        assert out["verdict"] not in F.FORBIDDEN_VERDICTS
        assert "clean" not in out["verdict"].lower()


def test_self_scan_observation_is_degraded_by_its_gaps(tree):
    out = N.self_scan(str(tree), "", provenance=N.NONE, sys_path=[str(tree)])
    obs = N.observation(out)
    assert obs.grade == F.HYPOTHESIS
    assert obs.telemetry_gaps
    assert obs.confidence == F.UNKNOWN


def test_self_scan_statement_says_it_cannot_certify_itself(tree):
    out = N.self_scan(str(tree), "", provenance=N.NONE, sys_path=[str(tree)])
    assert "cannot certify the scanner" in out["statement"]


# --- combining device and self scan -------------------------------------


def test_device_absence_with_an_unattested_scanner_is_inconclusive():
    combined = N.combine({"verdict": F.NO_EVIDENCE_FOUND},
                         {"integrity": {"verified": False}})
    assert combined["verdict"] == F.INCONCLUSIVE
    assert "unattested scanner" in combined["statement"]


def test_device_finding_stands_but_is_capped_when_the_scanner_is_unattested():
    combined = N.combine({"verdict": F.SUSPICIOUS_VERDICT},
                         {"integrity": {"verified": False}})
    assert combined["verdict"] == F.SUSPICIOUS_VERDICT
    assert combined["grade_cap"] == F.INFERRED


def test_attested_scanner_leaves_the_device_verdict_alone():
    combined = N.combine({"verdict": F.NO_EVIDENCE_FOUND},
                         {"integrity": {"verified": True}})
    assert combined["verdict"] == F.NO_EVIDENCE_FOUND
    assert combined["grade_cap"] is None


# --- calibration --------------------------------------------------------


def bench(pos_missed=0, neg_flagged=0, pos_abstained=0, neg_abstained=0,
          positives=40, negatives=40) -> K.Bench:
    b = K.Bench("corpus")
    for i in range(positives):
        produced = (F.INCONCLUSIVE if i < pos_abstained
                    else F.NO_EVIDENCE_FOUND if i < pos_abstained + pos_missed
                    else F.SUSPICIOUS_VERDICT)
        b.add(f"p{i}", "malicious", produced)
    for i in range(negatives):
        produced = (F.INCONCLUSIVE if i < neg_abstained
                    else F.SUSPICIOUS_VERDICT if i < neg_abstained + neg_flagged
                    else F.NO_EVIDENCE_FOUND)
        b.add(f"n{i}", "benign", produced)
    return b


def test_perfect_run_still_has_a_nonzero_error_bound():
    out = K.evaluate(bench())
    assert out["counts"][K.FN] == 0
    assert out["counts"][K.FP] == 0
    assert "at most" in out["zero_error_bound"]
    assert K.zero_error_upper_bound(40) > 0


def test_the_rule_of_three_bound_shrinks_with_corpus_size():
    assert K.zero_error_upper_bound(40) > K.zero_error_upper_bound(400)
    assert K.zero_error_upper_bound(0) == 1.0


def test_missed_positives_count_against_recall():
    out = K.evaluate(bench(pos_missed=4))
    assert out["counts"][K.FN] == 4
    assert out["false_negative_rate"] == pytest.approx(0.1)


def test_abstentions_count_as_misses_not_as_accuracy():
    out = K.evaluate(bench(pos_abstained=6))
    assert out["counts"][K.ABSTAINED_POSITIVE] == 6
    assert out["false_negative_rate"] == pytest.approx(0.15)
    assert any(g.startswith("abstentions:") for g in out["gaps"])


def test_false_alarms_are_measured_separately():
    out = K.evaluate(bench(neg_flagged=8))
    assert out["counts"][K.FP] == 8
    assert out["false_positive_rate"] == pytest.approx(0.2)
    assert out["specificity"] == pytest.approx(0.8)


def test_a_tiny_corpus_reports_no_rate():
    small = K.Bench("tiny").add("p1", "malicious", F.SUSPICIOUS_VERDICT)
    out = K.evaluate(small)
    assert out["measurable"] is False
    assert any("corpus_too_small" in g for g in out["gaps"])
    assert "guess with a decimal point" in out["statement"]


def test_zero_claim_is_never_allowed():
    out = K.evaluate(bench())
    assert out["zero_claim_allowed"] is False


def test_the_sentence_no_detector_can_support_is_refused():
    for phrase in ("no false positives", "NO FALSE NEGATIVES", "100% accurate",
                   "cannot be fooled"):
        with pytest.raises(K.CalibrationError):
            K.refuse_zero_claim(f"this tool has {phrase}")


def test_honest_wording_passes_the_checker():
    K.refuse_zero_claim(
        "0 missed in 40 positives: the false-negative rate is at most 7.2%, 95% CI"
    )


def test_wilson_interval_handles_zero_events():
    low, high = K.wilson(0, 40)
    assert low == 0.0
    assert 0.0 < high < 0.15


def test_bad_labels_and_verdicts_are_rejected():
    with pytest.raises(K.CalibrationError):
        K.Bench().add("x", "unknown", F.NO_EVIDENCE_FOUND)
    with pytest.raises(K.CalibrationError):
        K.Bench().add("x", "benign", "probably_fine")


def test_empty_corpus_is_refused():
    with pytest.raises(K.CalibrationError):
        K.evaluate(K.Bench())


def test_two_runs_with_overlapping_intervals_are_indistinguishable():
    a = K.evaluate(bench(pos_missed=2))
    b = K.evaluate(bench(pos_missed=3))
    out = K.compare(a, b)
    assert out["comparable"] is True
    assert out["claim"].startswith("indistinguishable")


def test_comparison_refuses_below_the_minimum_corpus():
    a = K.evaluate(bench(positives=5, negatives=5))
    out = K.compare(a, a)
    assert out["comparable"] is False

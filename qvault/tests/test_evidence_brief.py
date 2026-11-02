"""The evidence brief: custody defects must stop the filing, not decorate it.

Each test breaks one thing a prosecutor would break in cross-examination - a hash, a timestamp, an
acquisition method, the immutability of an original - and asserts the brief is refused.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from qvault.evidence_brief import (build_brief, lint_hypothesis, main, render_markdown,
                                   verify_brief)
from qvault.threatintel import DoctrineViolation, IntelligenceError

NOW = datetime(2026, 11, 2, 16, 0, tzinfo=timezone.utc)


def artifact(tmp_path, data=b"captured-bytes", name="sample.bin", **over):
    path = tmp_path / name
    path.write_bytes(data)
    os.chmod(path, 0o400)
    rec = {"name": name, "path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
           "acquired_at": "2026-11-01T09:30:00-04:00", "acquired_by": "analyst-a",
           "method": "passive_capture", "source": "consenting host"}
    rec.update(over)
    return rec


def case(tmp_path, **over):
    base = {
        "case": "2026-11-02-opx",
        "analyst": "analyst-a",
        "artifacts": [artifact(tmp_path)],
        "observations": [
            {"claim": "infrastructure_relationship", "subject": "campaign-a",
             "source": "published_report", "grade": "CORROBORATED",
             "entities": ["domain:bad.example", "ip:203.0.113.9"]},
            {"claim": "operator_attribution", "subject": "unknown-subject",
             "source": "provider_disclosure", "grade": "INFERRED",
             "entities": ["wallet:bc1qexample"]},
        ],
        "hypothesis": "The same builder appears to serve two campaigns, from shared artefacts.",
        "alternatives": {"operator_attribution": "a shared malware builder sold to unrelated buyers"},
    }
    base.update(over)
    return base


# ---------- custody ----------

def test_a_valid_case_produces_a_brief(tmp_path):
    brief = build_brief(case(tmp_path), now=NOW)
    assert brief["artifacts"][0]["immutable"] is True
    assert brief["manifest_sha256"]
    assert verify_brief(brief)


def test_a_hash_mismatch_is_refused(tmp_path):
    c = case(tmp_path)
    c["artifacts"][0]["sha256"] = "0" * 64
    with pytest.raises(DoctrineViolation, match="hash mismatch"):
        build_brief(c, now=NOW)


def test_a_writable_original_is_refused(tmp_path):
    c = case(tmp_path)
    os.chmod(c["artifacts"][0]["path"], 0o600)
    with pytest.raises(DoctrineViolation, match="writable"):
        build_brief(c, now=NOW)


def test_a_future_timestamp_is_refused(tmp_path):
    future = (NOW + timedelta(days=1)).isoformat()
    with pytest.raises(DoctrineViolation, match="future"):
        build_brief(case(tmp_path, artifacts=[artifact(tmp_path, acquired_at=future)]), now=NOW)


def test_a_naive_timestamp_is_refused(tmp_path):
    with pytest.raises(DoctrineViolation, match="timezone"):
        build_brief(case(tmp_path, artifacts=[artifact(tmp_path, acquired_at="2026-11-01T09:30:00")]),
                    now=NOW)


def test_an_undocumented_acquisition_method_is_refused(tmp_path):
    with pytest.raises(DoctrineViolation, match="method"):
        build_brief(case(tmp_path, artifacts=[artifact(tmp_path, method="somehow")]), now=NOW)


def test_an_unattributed_artefact_is_refused(tmp_path):
    with pytest.raises(DoctrineViolation, match="acquiring party"):
        build_brief(case(tmp_path, artifacts=[artifact(tmp_path, acquired_by="  ")]), now=NOW)


def test_a_missing_artefact_is_refused(tmp_path):
    # Build the case first: the helper writes its default artefact, so deleting before would be undone.
    c = case(tmp_path)
    os.remove(c["artifacts"][0]["path"])
    with pytest.raises(DoctrineViolation, match="not found"):
        build_brief(c, now=NOW)


# ---------- attribution ----------

@pytest.mark.parametrize("text", [
    "The C2 is operated by Ivan Petrov.",
    "This wallet belongs to Ivan Petrov.",
    "The operator is named Ivan Petrov.",
    "The account was identified as Ivan Petrov.",
])
def test_phrasing_that_names_a_person_is_refused(text):
    with pytest.raises(DoctrineViolation, match="person"):
        lint_hypothesis(text)


def test_a_hypothesis_cannot_be_declared_corroborated(tmp_path):
    with pytest.raises(DoctrineViolation, match="hypothesis is not"):
        build_brief(case(tmp_path, hypothesis_grade="CORROBORATED"), now=NOW)


def test_attribution_without_a_competing_explanation_is_refused(tmp_path):
    with pytest.raises(DoctrineViolation, match="competing explanation"):
        build_brief(case(tmp_path, alternatives={}), now=NOW)


def test_an_empty_evidence_set_is_refused(tmp_path):
    with pytest.raises(IntelligenceError, match="rumour"):
        build_brief(case(tmp_path, artifacts=[]), now=NOW)


# ---------- the document ----------

def test_the_brief_states_what_it_does_not_establish(tmp_path):
    brief = build_brief(case(tmp_path), now=NOW)
    text = render_markdown(brief)
    assert "does not identify any person" in text
    assert "who controls a wallet" in " ".join(brief["does_not_establish"])
    assert "contacts nobody" in text
    assert "Internet Crime Complaint Center" in text


def test_editing_a_brief_breaks_its_manifest(tmp_path):
    brief = build_brief(case(tmp_path), now=NOW)
    brief["hypothesis_grade"] = "CONFIRMED"
    assert verify_brief(brief) is False


def test_grades_are_computed_not_declared(tmp_path):
    brief = build_brief(case(tmp_path), now=NOW)
    attribution = next(h for h in brief["hypotheses"] if h["claim"] == "operator_attribution")
    assert attribution["grade"] == "HYPOTHESIS"


# ---------- CLI ----------

def test_cli_writes_the_brief_and_exits_zero(tmp_path, capsys):
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(case(tmp_path)))
    out = tmp_path / "brief.md"
    js = tmp_path / "brief.json"
    assert main(["build", str(case_path), "--out", str(out), "--json", str(js)]) == 0
    assert "Evidence brief" in out.read_text()
    assert main(["verify", str(js)]) == 0


def test_cli_refuses_a_broken_case_with_a_nonzero_exit(tmp_path, capsys):
    bad = case(tmp_path)
    bad["artifacts"][0]["sha256"] = "1" * 64
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(bad))
    assert main(["build", str(case_path), "--out", str(tmp_path / "b.md")]) == 2
    assert "refused" in capsys.readouterr().err

"""The security report is generated, so the tests can check it against the tree it describes."""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
import gen_security_report as G  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault import denial as D  # noqa: E402
from qvault import findings as F  # noqa: E402

PAGE = ROOT / "report" / "SECURITY_REPORT.md"


@pytest.fixture(scope="module")
def text() -> str:
    return PAGE.read_text()


def test_the_page_matches_its_generator(text):
    assert text == tables.align(G.render()), "report/SECURITY_REPORT.md is stale"


def test_the_report_names_the_current_version(text):
    assert f"qvault {__version__}" in text


def test_the_report_contains_no_absolute_reassurance(text):
    with pytest.raises(ValueError):
        G.assert_no_overclaim("this scans the host and guarantees it is malware-free")


def test_every_open_finding_carries_a_falsifier(text):
    for title, ref, grade, _body, falsifier in G.OPEN_FINDINGS:
        assert title in text
        assert falsifier in text, f"{ref} has no falsifier in the report"


def test_open_finding_grades_come_from_the_shared_vocabulary(text):
    for _title, ref, grade, _body, _falsifier in G.OPEN_FINDINGS:
        assert grade in F.GRADES, ref
        assert f"{ref} - " in text


def test_the_census_matches_the_ledger(text):
    rows = list(csv.DictReader((ROOT / "report" / "CLAIMS_LEDGER.csv").open()))
    for grade in F.GRADES:
        expected = sum(1 for r in rows if r["tag"] == grade)
        assert re.search(rf"\|\s*{grade}\s*\|\s*{expected}\s*\|", text), f"{grade} census is wrong"


def test_the_unverified_count_is_stated(text):
    rows = list(csv.DictReader((ROOT / "report" / "CLAIMS_LEDGER.csv").open()))
    unverified = sum(1 for r in rows if r["verification"] == "none")
    assert f"**{unverified} claims carry no independent verification.**" in text


def test_every_gate_is_listed(text):
    import gates
    for gid, _name, _fn in gates.GATES:
        assert re.search(rf"\|\s*{gid}\s*\|", text), f"{gid} is missing from the report"


def test_every_posture_is_listed_with_its_expiry(text):
    for posture in D.POSTURES:
        assert f"`{posture.name}`" in text
        assert posture.restored_when in text


def test_the_report_refuses_to_call_the_system_clean(text):
    lowered = text.lower()
    assert "is malware-free" not in lowered
    assert "absence of a finding is not evidence of absence" in lowered

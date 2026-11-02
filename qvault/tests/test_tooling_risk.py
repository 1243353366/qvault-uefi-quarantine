"""The risk register is only useful if it is complete, so completeness is a test."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
import gen_tooling_risk as G  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault import findings as F  # noqa: E402

PAGE = ROOT / "report" / "TOOLING_RISK.md"


@pytest.fixture(scope="module")
def text() -> str:
    return PAGE.read_text()


def test_the_page_matches_its_generator(text):
    assert text == tables.align(G.render()), "report/TOOLING_RISK.md is stale"


def test_the_register_covers_every_module_that_parses_input():
    missing = G.detected() - set(G.REGISTER)
    assert not missing, f"unregistered: {sorted(missing)}"


def test_an_unregistered_module_is_refused(monkeypatch):
    monkeypatch.setattr(G, "detected", lambda: {"ingest.py", "brand_new_parser.py"})
    with pytest.raises(ValueError, match="brand_new_parser"):
        G.assert_register_complete()


def test_every_entry_states_its_gap():
    for module, entry in G.REGISTER.items():
        for field in ("consumes", "guard", "gap"):
            assert entry[field].strip(), f"{module} has an empty {field}"


def test_the_unguarded_modules_say_so(text):
    unguarded = [m for m, e in G.REGISTER.items() if e["guard"].startswith("none observed")]
    assert unguarded, "the register claims every module has a guard; that was not true when written"
    assert "`none observed` rows" in text or "none observed" in text


def test_the_register_admits_there_is_no_fuzzing(text):
    assert "has been fuzzed" in text
    assert (ROOT / "tools").is_dir() and not list((ROOT / "tools").glob("*fuzz*"))


def test_grades_are_from_the_shared_vocabulary():
    for _statement, grade in G.GLOBAL:
        assert grade in F.GRADES


def test_the_page_does_not_claim_the_parsers_are_safe(text):
    assert "does not claim the parsers are safe" in text


def test_the_page_names_the_current_version(text):
    assert f"Release **{__version__}**" in text


@pytest.mark.parametrize("name", ["SECURITY.md", "CONTRIBUTING.md", "PROVENANCE.md"])
def test_the_policy_documents_exist_and_cross_reference(name):
    body = (ROOT / name).read_text()
    assert "TOOLING_RISK.md" in body or "CLAIMS_LEDGER.csv" in body or "NOTICE" in body


def test_provenance_states_that_tags_are_unsigned():
    """Verification rests on a commit hash and CI, and the file has to say so."""
    body = (ROOT / "PROVENANCE.md").read_text()
    assert "not cryptographically signed" in body
    assert "no signing key" in body


def test_security_policy_routes_reports_to_private_advisories():
    body = (ROOT / "SECURITY.md").read_text()
    assert "private vulnerability reporting" in body
    assert "no bug bounty" in body.lower() or "no bug bounty and no response sla" in body.lower()

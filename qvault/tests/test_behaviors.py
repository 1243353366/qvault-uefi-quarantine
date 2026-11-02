"""The behaviour matrix, held to its own promise.

A matrix that names a control which does not exist is worse than no matrix: it says a
behaviour is handled. Every row therefore resolves, states a limit, and cites a source that
is in the bibliography.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

import sys as _sys  # noqa: E402
from pathlib import Path as _Path  # noqa: E402
_sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / "tools"))
import tables  # noqa: E402
from qvault import behaviors as B

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "report" / "UEFI_Malware_Deep_Dive_Report.md"


# --- resolution and shape -------------------------------------------------------------

def test_every_behaviour_resolves_to_real_code():
    B.assert_resolves()


def test_a_behaviour_pointing_at_a_missing_symbol_is_rejected():
    ghost = B.Behaviour(id="ghost", family="test", attck="T1547.001", technique="x",
                        evidence="x", behaviour="x", control="x", module="qvault.persistence",
                        symbol="no_such_function", coverage=B.IMPLEMENTED, limit="x",
                        source_bib="44")
    with pytest.raises(B.BehaviourError):
        B.resolve(ghost)


def test_every_behaviour_states_a_limit():
    for entry in B.BEHAVIOURS:
        assert entry.limit.strip(), entry.id


def test_an_unknown_coverage_value_is_rejected():
    with pytest.raises(B.BehaviourError):
        B._b(id="bad", family="test", attck="T1547.001", technique="x", evidence="x",
             behaviour="x", control="x", module="qvault.persistence",
             symbol="MECHANISMS", coverage="probably", limit="x", source_bib="44")


def test_technique_ids_are_well_formed():
    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for entry in B.BEHAVIOURS:
        assert pattern.match(entry.attck), entry.id


def test_ids_are_unique():
    ids = [b.id for b in B.BEHAVIOURS]
    assert len(ids) == len(set(ids))


# --- citations -----------------------------------------------------------------------

def test_every_source_is_in_the_bibliography():
    text = REPORT.read_text()
    numbered = set(re.findall(r"^(\d+)\. ", text, flags=re.MULTILINE))
    for entry in B.BEHAVIOURS:
        assert entry.source_bib in numbered, f"{entry.id} cites {entry.source_bib}"


def test_every_cited_technique_appears_with_its_identifier():
    """The bibliography entry must actually name the technique the row claims."""
    text = REPORT.read_text()
    for entry in B.BEHAVIOURS:
        matches = re.findall(rf"^{entry.source_bib}\..*?(?=\n\d+\. |\Z)", text,
                            flags=re.MULTILINE | re.DOTALL)
        assert matches, entry.id
        assert entry.attck in matches[0], f"{entry.id}: {entry.source_bib} does not cite {entry.attck}"


# --- honesty about gaps --------------------------------------------------------------

def test_the_matrix_reports_gaps_rather_than_claiming_total_coverage():
    assert B.gaps(), "a matrix with no gaps is a matrix that is not looking"
    assert any(g["coverage"] == B.ABSENT for g in B.gaps())


def test_exploitation_is_declared_out_of_boundary():
    ids = {b.id: b for b in B.BEHAVIOURS}
    for name in ("exploit-kernel", "exploit-browser-sandbox"):
        assert ids[name].coverage == B.ABSENT
        assert "out of this boundary" in ids[name].control.lower()


def test_no_row_claims_coverage_without_a_control():
    for entry in B.BEHAVIOURS:
        if entry.coverage == B.IMPLEMENTED:
            assert entry.control.strip() and entry.control.lower() != "none"


def test_the_requested_families_are_all_present():
    families = set(B.by_family())
    for expected in ("persistence", "pre-os", "execution-hijack", "execution",
                     "anti-forensics", "exploitation", "stealth", "credential"):
        assert expected in families, expected


# --- the generated document ----------------------------------------------------------

def test_the_report_matches_the_catalogue():
    """Anti-drift: the document is a render of the code, so it cannot describe old code."""
    sys.path.insert(0, str(ROOT / "tools"))
    import gen_behavior_matrix  # noqa: PLC0415

    on_disk = (ROOT / "report" / "THREAT_BEHAVIOR_MATRIX.md").read_text()
    assert on_disk == tables.align(gen_behavior_matrix.render()), (
        "report/THREAT_BEHAVIOR_MATRIX.md is stale; run tools/gen_behavior_matrix.py")


def test_the_document_names_every_behaviour():
    on_disk = (ROOT / "report" / "THREAT_BEHAVIOR_MATRIX.md").read_text()
    for entry in B.BEHAVIOURS:
        assert f"`{entry.id}`" in on_disk


# --- wiring into the persistence layer ----------------------------------------------

def test_ifeo_is_covered_as_a_mechanism_because_attck_names_it():
    from qvault import persistence as P

    assert "ifeo" in P.MECHANISMS
    row = {r["mechanism"]: r for r in P.assess(
        [P.AutostartEntry("ifeo", "sethc.exe", "C:\\Tools\\dbg.exe")],
        basis="offline_image")["matrix"]}["ifeo"]
    assert "ifeo_debugger" in row["signals"]

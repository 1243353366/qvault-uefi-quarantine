"""The pinned in-the-wild reference set: provenance, integrity, and honest boundaries."""
import json
import re
import sys
from pathlib import Path

import pytest

from qvault import wild as W

ROOT = Path(__file__).resolve().parents[2]


def test_the_index_is_structurally_valid():
    W.assert_dataset_integrity()


def test_upstream_is_pinned_to_a_commit_not_a_branch():
    commit = W.load()["source"]["commit"]
    assert re.fullmatch(r"[0-9a-f]{40}", commit)
    assert commit not in ("main", "master", "HEAD")


def test_the_licence_is_recorded_and_permissive():
    assert W.load()["source"]["license"] == "Apache-2.0"


def test_the_archive_hash_is_recorded():
    assert re.fullmatch(r"[0-9a-f]{64}", W.load()["source"]["tarball_sha256"])


def test_every_entry_has_a_valid_cve_and_a_four_digit_year():
    for entry in W.entries():
        assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", entry["cve"])
        assert re.fullmatch(r"\d{4}", entry["year"])


def test_entries_are_unique():
    cves = [e["cve"] for e in W.entries()]
    assert len(cves) == len(set(cves))


def test_per_file_hashes_are_sha256():
    for entry in W.entries():
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), entry["cve"]
        assert entry["bytes"] > 0


def test_xml_the_source_documents_live_under_the_rca_tree():
    for entry in W.entries():
        assert entry["path"].startswith("0day-RCAs/")


def test_the_dataset_is_not_empty_and_is_not_tiny():
    assert W.summary()["entries"] >= 60


def test_year_folders_are_exploitation_years_which_may_differ_from_cve_years():
    differences = W.year_is_exploitation_year()
    assert differences, "the corpus should contain at least one such case"
    for cve, detail in differences.items():
        assert detail["cve_year"] != detail["exploited_year"]
        assert detail["exploited_year"] in cve or detail["cve_year"] in cve


def test_known_data_gaps_are_recorded_rather_than_hidden():
    """One RCA has no heading title upstream; that is upstream's gap, not a parse failure."""
    missing = [e["cve"] for e in W.entries() if not e["title"]]
    assert missing == ["CVE-2021-30858"], missing


def test_classification_records_its_basis_and_evidence():
    for entry in W.entries():
        result = W.classify(entry)
        assert "human adjudication" in result["basis"]
        for name, hits in result["evidence"].items():
            assert hits
            haystack = " ".join(str(entry.get(k) or "") for k in
                                ("title", "product", "affected_versions")).lower()
            for hit in hits:
                assert hit in haystack, f"{entry['cve']}: {hit} not actually present"


def test_classification_never_returns_a_finding_grade():
    for entry in W.entries():
        assert "grade" not in W.classify(entry)
        assert "CLEAN" not in json.dumps(W.classify(entry))


def test_the_boundary_statement_does_not_claim_detection():
    assessment = W.boundary_assessment()
    assert "does not detect exploitation" in assessment["statement"]
    assert assessment["touching_persistence_or_boot"] < assessment["entries"]


def test_the_boundary_counts_only_what_it_claims_to_count():
    assessment = W.boundary_assessment()
    touching = sum(1 for e in W.entries()
                   if {"persistence", "firmware_boot"} & set(W.classify(e)["classes"]))
    assert assessment["touching_persistence_or_boot"] == touching


def test_the_report_matches_the_pinned_index():
    sys.path.insert(0, str(ROOT / "tools"))
    import gen_in_the_wild  # noqa: PLC0415

    on_disk = (ROOT / "report" / "IN_THE_WILD.md").read_text()
    assert on_disk == gen_in_the_wild.render(), (
        "report/IN_THE_WILD.md is stale; run tools/gen_in_the_wild.py")


def test_the_vendored_snapshot_is_documented_and_small():
    source = ROOT / "vendor" / "p0_0days" / "SOURCE.md"
    assert source.exists()
    text = source.read_text()
    assert "e21be4bb01c617736d35350fc2f64cd2a42a3721" in text
    assert "Apache-2.0" in text
    assert (ROOT / "vendor" / "p0_0days" / "index.json").stat().st_size < 200_000


def test_a_pin_without_a_commit_is_refused(monkeypatch, tmp_path):
    data = json.loads((ROOT / "vendor" / "p0_0days" / "index.json").read_text())
    data["source"]["commit"] = "main"
    bad = tmp_path / "index.json"
    bad.write_text(json.dumps(data))
    monkeypatch.setattr(W, "INDEX", bad)
    with pytest.raises(W.WildError) as err:
        W.assert_dataset_integrity()
    assert "40-character sha" in str(err.value)


def test_attribution_records_the_collaborator_refusal():
    """GitHub refuses organisations as outside collaborators; the record must say so."""
    text = (ROOT / "CONTRIBUTORS.md").read_text()
    assert "googleprojectzero" in text
    assert "not a user" in text
    assert "no invitation is pending" in text
    notice = (ROOT / "NOTICE").read_text()
    assert "Apache License, Version 2.0" in notice
    assert "0days-in-the-wild" in notice

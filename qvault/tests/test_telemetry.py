"""Telemetry coverage: every mechanism has an evidence source or a stated reason."""
import re
from pathlib import Path

import pytest

from qvault import persistence as P
from qvault import telemetry as T

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "report" / "UEFI_Malware_Deep_Dive_Report.md"


def test_the_mapping_is_complete_and_resolvable():
    T.assert_complete()


def test_every_mechanism_has_a_mapping_entry():
    assert set(T.MECHANISM_SOURCES) == set(P.MECHANISMS)


def test_an_unmapped_mechanism_is_refused_rather_than_blank():
    with pytest.raises(T.TelemetryError):
        T.sources_for("no_such_mechanism")


def test_every_cited_source_exists():
    for mechanism, ids in T.MECHANISM_SOURCES.items():
        for source_id in ids:
            assert source_id in T.SOURCES, f"{mechanism} -> {source_id}"


def test_event_ids_are_numeric():
    for source in T.SOURCES.values():
        assert all(e.isdigit() for e in source.event_ids), source.id


def test_every_source_names_fields_to_inspect():
    for source in T.SOURCES.values():
        assert source.fields, source.id


def test_sigma_rule_ids_are_uuids():
    for rule in T.SIGMA:
        assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                            rule.rule_id), rule.rule_id


def test_sigma_rules_point_at_real_repository_paths():
    for rule in T.SIGMA:
        assert rule.path.startswith("rules/windows/")
        assert rule.path.endswith(".yml")


def test_a_host_cannot_testify_about_rootkits_or_bootkits():
    blind = T.mechanisms_without_host_evidence()
    assert blind == ["bootkit_boot", "rootkit_hiding"]
    for mechanism in blind:
        assert mechanism in T.NO_TELEMETRY


def test_fileless_is_execution_time_only_not_invisible():
    assert "fileless" in T.EXECUTION_TIME_ONLY
    assert "fileless" not in T.NO_TELEMETRY
    assert T.MECHANISM_SOURCES["fileless"], "fileless must map to execution-time telemetry"


def test_no_mechanism_is_marked_unobservable_and_wired_to_a_source():
    for mechanism in T.NO_TELEMETRY:
        assert T.MECHANISM_SOURCES[mechanism] == ()


def test_ifeo_and_boot_execute_are_wired_to_registry_telemetry():
    for mechanism in ("ifeo", "boot_execute", "run_key"):
        assert T.MECHANISM_SOURCES[mechanism] == ("sysmon_registry_set",)


def test_sources_for_returns_a_copy():
    first = T.sources_for("run_key")
    first.append("mutated")
    assert T.sources_for("run_key") == ["sysmon_registry_set"]


def test_every_source_cites_a_bibliography_entry():
    text = REPORT.read_text()
    numbered = set(re.findall(r"^(\d+)\. ", text, flags=re.MULTILINE))
    for source in T.SOURCES.values():
        assert source.source_bib in numbered, source.id


def test_the_rendered_map_matches_the_mapping():
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    import gen_telemetry_map  # noqa: PLC0415

    on_disk = (ROOT / "report" / "TELEMETRY_MAP.md").read_text()
    assert on_disk == gen_telemetry_map.render(), (
        "report/TELEMETRY_MAP.md is stale; run tools/gen_telemetry_map.py")


def test_the_map_names_every_mechanism_and_its_sources():
    on_disk = (ROOT / "report" / "TELEMETRY_MAP.md").read_text()
    for mechanism in P.MECHANISMS:
        assert f"`{mechanism}`" in on_disk
    for source in T.SOURCES:
        assert f"`{source}`" in on_disk

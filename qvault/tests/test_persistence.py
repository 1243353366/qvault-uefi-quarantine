"""The persistence detection contract.

Four states, one per mechanism, and no way to turn "we did not look" into "it is not
there". The tests below are the contract: result classes, exact matching, grade ceilings,
and the oracle/ledger hygiene the layer is required to keep.
"""
import csv
from pathlib import Path

import pytest

from qvault import findings as F
from qvault import grading as G
from qvault import persistence as P
from qvault import separation as S


def entry(mechanism="run_key", name="e", command="C:\\x\\y.exe", **kw):
    return P.AutostartEntry(mechanism=mechanism, name=name, command=command, **kw)


def rows(result):
    return {row["mechanism"]: row for row in result["matrix"]}


def assess(entries=(), **kw):
    kw.setdefault("basis", "offline_image")
    return P.assess(entries, **kw)


# --- the descriptor contract ---------------------------------------------------------

def test_every_source_mechanism_has_a_descriptor():
    for key in ("run_key", "startup_folder", "scheduled_task", "service", "boot_execute",
                "bho", "appinit_dll", "dll_search_order", "rootkit_hiding", "bootkit_boot",
                "fileless"):
        assert key in P.MECHANISMS, key
    assert len(P.MECHANISMS) >= 11


def test_every_descriptor_states_what_it_is_and_what_removes_it():
    for mechanism in P.MECHANISMS.values():
        assert mechanism.name and mechanism.observable_path
        assert mechanism.control and mechanism.benign_default
    P.assert_catalogue_integrity()


def test_an_observable_mechanism_without_a_predicate_is_rejected():
    with pytest.raises(P.PersistenceError):
        P._m("broken", "Broken", "somewhere", "benign", "control", None)


def test_an_unobservable_mechanism_may_not_carry_a_predicate():
    with pytest.raises(P.PersistenceError):
        P._m("broken", "Broken", "nowhere", "n/a", "control", P._generic, observable=False)


# --- four result classes, and no clean ---------------------------------------------

def test_the_layer_has_no_clean_state():
    assert P.CLEAN_STATES == frozenset()
    assert "CLEAN" not in P.RESULT_CLASSES
    with pytest.raises(P.PersistenceError):
        P.assert_not_clean("CLEAN")


@pytest.mark.parametrize("mechanism", ["rootkit_hiding", "bootkit_boot", "fileless"])
def test_unobservable_mechanisms_return_unknown_not_observable(mechanism):
    row = rows(assess([entry(mechanism, "x")]))[mechanism]
    assert row["result"] == P.UNKNOWN_NOT_OBSERVABLE
    assert row["grade"] == F.UNKNOWN
    assert "cannot confirm or exclude" in row["statement"]


def test_a_mechanism_absent_from_the_snapshot_is_not_observed_not_benign():
    row = rows(assess([entry("run_key", "x")]))["service"]
    assert row["result"] == P.NOT_OBSERVED
    assert "not evidence it is absent" in row["statement"]


def test_not_observed_and_not_observable_stay_distinct():
    result = assess([entry("run_key", "x")])
    assert P.NOT_OBSERVED != P.UNKNOWN_NOT_OBSERVABLE
    assert "service" in result["coverage"]["not_observed"]
    assert "rootkit_hiding" in result["coverage"]["not_observable"]
    assert not set(result["coverage"]["not_observed"]) & set(result["coverage"]["not_observable"])


def test_a_quiet_known_entry_is_benign_not_detected():
    row = rows(assess([entry("run_key", "OneDrive",
                             "C:\\Program Files\\OneDrive\\OneDrive.exe", signed=True)]))["run_key"]
    assert row["result"] == P.BENIGN
    assert row["signals"] == []
    assert "consistent with its benign twin" in row["statement"]


def test_signals_produce_detected_with_a_grade():
    row = rows(assess([entry("run_key", "u", "C:\\Users\\b\\AppData\\Roaming\\u.exe",
                             signed=False)]))["run_key"]
    assert row["result"] == P.DETECTED
    assert set(row["signals"]) == {"user_writable_location", "unsigned_binary"}
    assert row["grade"] == F.INFERRED


def test_every_mechanism_appears_in_every_assessment():
    for snapshot in ([], [entry("run_key", "x")], [entry("fileless", "y")]):
        result = assess(snapshot)
        assert len(result["matrix"]) == len(P.MECHANISMS)
        assert {row["mechanism"] for row in result["matrix"]} == set(P.MECHANISMS)


# --- BootExecute: exact match, not containment ---------------------------------------

def test_the_default_bootexecute_is_benign():
    assert rows(assess([entry("boot_execute", "d", P.BOOT_EXECUTE_DEFAULT)]))["boot_execute"]["signals"] == []


def test_a_payload_appended_to_the_default_is_detected():
    """The original bug: containment passed this, equality does not."""
    value = P.BOOT_EXECUTE_DEFAULT + " \\??\\C:\\Windows\\System32\\drivers\\x.sys"
    row = rows(assess([entry("boot_execute", "x", value)]))["boot_execute"]
    assert row["signals"] == ["boot_execute_nonstandard"]
    assert row["result"] == P.DETECTED


def test_case_and_spacing_differences_do_not_produce_a_false_positive():
    assert rows(assess([entry("boot_execute", "d", "  AUTOCHECK   autochk *  ")]))["boot_execute"]["signals"] == []


# --- per-mechanism predicates --------------------------------------------------------

def test_appinit_only_flags_a_populated_value():
    assert rows(assess([entry("appinit_dll", "e", "")]))["appinit_dll"]["result"] == P.BENIGN
    assert rows(assess([entry("appinit_dll", "s", "C:\\x\\hook.dll")]))["appinit_dll"]["signals"] == ["appinit_populated"]


def test_service_flags_only_a_binary_outside_system32():
    inside = rows(assess([entry("service", "s", "C:\\Windows\\System32\\s.exe", signed=True)]))["service"]
    assert "service_outside_system32" not in inside["signals"]
    outside = rows(assess([entry("service", "s", "C:\\Tools\\s.exe", signed=True)]))["service"]
    assert "service_outside_system32" in outside["signals"]


def test_hive_flags_only_a_path_outside_config():
    ok = rows(assess([entry("hive_load", "h", "", location="C:\\Windows\\System32\\config\\SYSTEM")]))["hive_load"]
    assert ok["signals"] == []
    bad = rows(assess([entry("hive_load", "h", "", location="C:\\Users\\b\\evil.hiv")]))["hive_load"]
    assert "hive_from_writable_path" in bad["signals"]


# --- grading: the basis is the ceiling, the signals are the claim --------------------

def test_a_live_host_read_grades_nothing_however_suspicious():
    result = assess([entry("run_key", "u", "C:\\Temp\\a.exe", signed=False, hidden=True)],
                    basis="live_host")
    row = rows(result)["run_key"]
    assert row["grade"] == F.UNKNOWN
    assert "self-report" in row["statement"]


@pytest.mark.parametrize("signals,expected", [(0, F.UNKNOWN), (1, F.HYPOTHESIS), (2, F.INFERRED)])
def test_signal_count_maps_to_a_proposed_grade(signals, expected):
    assert G.proposed_grade(signals) == expected


def test_an_offline_image_caps_at_corroborated_and_never_grammar_grabs_it():
    assert G.ceiling("offline_image") == F.CORROBORATED
    assert G.cap_grade(basis="offline_image", signal_count=2) == F.INFERRED


def test_an_attested_image_is_confirmed_only_when_the_attestation_verified():
    assert G.ceiling("attested_image", "verified") == F.CONFIRMED
    assert G.ceiling("attested_image", "absent") == G.ceiling("offline_image")
    assert G.ceiling("attested_image", "unknown") == G.ceiling("offline_image")


def test_a_confirmed_ceiling_is_a_limit_not_a_target():
    assert G.cap_grade(basis="attested_image", signal_count=2,
                       attestation_state="verified") == F.INFERRED


@pytest.mark.parametrize("signal_count", [0, 1, 2, 5])
def test_a_stronger_basis_never_lowers_a_grade(signal_count):
    weak = G.cap_grade(basis="offline_image", signal_count=signal_count)
    strong = G.cap_grade(basis="attested_image", signal_count=signal_count,
                         attestation_state="verified")
    order = list(reversed(F.GRADES))
    assert order.index(strong) >= order.index(weak)


def test_an_unverified_attestation_cannot_be_used_to_elevate():
    elevated = G.cap_grade(basis="attested_image", signal_count=2, attestation_state="verified")
    unverified = G.cap_grade(basis="attested_image", signal_count=2, attestation_state="absent")
    assert G.explain(basis="attested_image", signal_count=2,
                     attestation_state="absent")["ceiling"] == F.CORROBORATED
    assert elevated == unverified == F.INFERRED


def test_the_grading_api_refuses_what_it_cannot_reason_about():
    with pytest.raises(G.GradingError):
        G.cap_grade(basis="vibes", signal_count=1)
    with pytest.raises(G.GradingError):
        G.cap_grade(basis="offline_image", signal_count=1, attestation_state="probably")
    with pytest.raises(G.GradingError):
        G.proposed_grade(-1)


def test_the_persistence_layer_does_not_reach_into_rank_internals():
    source = Path(P.__file__).read_text()
    assert "_RANK" not in source
    assert "grade_ceiling" not in source, "grading arithmetic belongs in grading.py"


# --- refusals are coarse -------------------------------------------------------------

def test_an_unknown_mechanism_error_does_not_enumerate_the_catalogue():
    with pytest.raises(P.PersistenceError) as err:
        assess([entry("magic_persistence", "x")])
    message = str(err.value)
    assert "magic_persistence" not in message
    assert not any(m in message for m in P.MECHANISMS)


def test_an_unknown_basis_is_refused():
    with pytest.raises(G.GradingError):
        P.assess([], basis="vibes")


def test_the_answer_shape_does_not_depend_on_the_snapshot():
    shapes = {repr(sorted(r.keys())) for r in assess([])["matrix"]}
    shapes |= {repr(sorted(r.keys())) for r in assess([entry("run_key", "x")])["matrix"]}
    assert len(shapes) == 1, shapes


def test_live_capture_requires_an_isolated_attested_path():
    with pytest.raises(S.ScopeError):
        P.assess([], scope=S.LIVE_CAPTURE)
    assert P.assess([], scope=S.LIVE_CAPTURE, isolated=True, attested=True)["basis"] == "synthetic"


# --- summary and the ledger contract -------------------------------------------------

def test_the_summary_never_offers_a_clean_verdict():
    summary = P.summarise(assess([entry("run_key", "x")]))
    assert summary["clean_state_available"] is False
    assert "CLEAN" not in repr(summary)


def test_statement_text_never_uses_the_word_clean():
    for row in assess([entry("run_key", "x")])["matrix"]:
        assert "clean" not in row["statement"].lower() or "not" in row["statement"].lower()


def test_the_claims_ledger_obeys_its_own_contract():
    """Guards the two mistakes made while writing this commit: a URL as a bibliography
    key, and a ninth column shifting tag and verification out of place."""
    path = Path(__file__).resolve().parents[2] / "report" / "CLAIMS_LEDGER.csv"
    rows_ = list(csv.reader(path.open()))
    header, body = rows_[0], rows_[1:]
    assert len(header) == 8, header
    assert all(len(row) == 8 for row in body)
    for row in body:
        identified, _section, _claim, bib, _locator, tag, verification, falsifier = row
        assert tag in (F.CONFIRMED, F.CORROBORATED, F.INFERRED, F.HYPOTHESIS, F.UNKNOWN), identified
        assert verification in ("independent", "none"), identified
        if verification == "independent" and tag in (F.CONFIRMED, F.CORROBORATED,
                                                    F.INFERRED, F.HYPOTHESIS):
            assert bib.isdigit() or bib in ("n/a", ""), f"{identified}: bibliography {bib!r}"
        assert len(falsifier) > 20, identified

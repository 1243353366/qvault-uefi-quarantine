"""The autostart surface, as an instrument.

Two failure modes are tested as hard as the detections themselves: accusing legitimate
software, and reporting a mechanism as clean because nothing was looked at.
"""
import pytest

from qvault import findings as F
from qvault import persistence as P
from qvault import separation as S


def run(mechanism="run_key", name="entry", command="C:\\x\\y.exe", **kw):
    return P.AutostartEntry(mechanism=mechanism, name=name, command=command, **kw)


def assess(entries, **kw):
    kw.setdefault("basis", "offline_image")
    return P.assess(entries, **kw)


# --- catalogue -----------------------------------------------------------------------

def test_the_catalogue_carries_every_mechanism_from_the_source():
    assert len(P.MECHANISMS) >= 11
    for key in ("run_key", "startup_folder", "scheduled_task", "service", "boot_execute",
                "bho", "appinit_dll", "dll_search_order", "rootkit_hiding",
                "bootkit_boot", "fileless"):
        assert key in P.MECHANISMS, key


def test_every_mechanism_states_a_benign_twin_and_a_control():
    P.assert_catalogue_integrity()
    for key, meta in P.MECHANISMS.items():
        assert meta["control"], key
        assert meta["benign"], key


def test_a_mechanism_without_a_benign_reading_is_rejected(monkeypatch):
    broken = dict(P.MECHANISMS["run_key"]); broken["benign"] = ""
    monkeypatch.setattr(P, "MECHANISMS", {**P.MECHANISMS, "run_key": broken})
    with pytest.raises(P.PersistenceError):
        P.assert_catalogue_integrity()


# --- mechanisms that a snapshot cannot see ------------------------------------------

@pytest.mark.parametrize("mechanism", ["rootkit_hiding", "bootkit_boot", "fileless"])
def test_unobservable_mechanisms_are_marked_not_guessed(mechanism):
    result = assess([run(mechanism, "hidden")])
    observation = result["observations"][0]
    assert observation["observable"] is False
    assert observation["grade"] == F.UNKNOWN
    assert "not observable" in observation["statement"]


def test_they_are_reported_as_not_observable_in_coverage():
    assert P.coverage(set())["not_observable"] == ["bootkit_boot", "fileless",
                                                   "rootkit_hiding"]


# --- signal detection ---------------------------------------------------------------

def test_the_default_boot_execute_value_is_not_flagged():
    assert assess([run("boot_execute", "default", "autocheck autochk *")])["observations"][0]["signals"] == []


def test_an_extra_boot_execute_entry_is_flagged():
    observation = assess([run("boot_execute", "extra", "autocheck autochk * \\??\\C:\\x.sys")])["observations"][0]
    assert "boot_execute_nonstandard" in observation["signals"]


def test_appinit_is_flagged_only_when_populated():
    assert assess([run("appinit_dll", "empty", "")])["observations"][0]["signals"] == []
    assert "appinit_populated" in assess([run("appinit_dll", "set", "C:\\x\\hook.dll")])["observations"][0]["signals"]


def test_a_service_inside_system32_is_not_flagged_for_path():
    inside = assess([run("service", "svc", "C:\\Windows\\System32\\svc.exe", signed=True)])
    assert "service_outside_system32" not in inside["observations"][0]["signals"]
    outside = assess([run("service", "svc", "C:\\Tools\\svc.exe", signed=True)])
    assert "service_outside_system32" in outside["observations"][0]["signals"]


def test_a_hive_outside_config_is_flagged():
    observation = assess([run("hive_load", "rogue", "", location="\\\\.\\C:\\Users\\bob\\evil.hiv")])["observations"][0]
    assert "hive_from_writable_path" in observation["signals"]


def test_a_hidden_task_is_flagged():
    observation = assess([run("scheduled_task", "t", "C:\\x.exe", hidden=True)])["observations"][0]
    assert "hidden_task" in observation["signals"]


def test_a_lolbin_with_an_encoded_command_is_two_signals():
    entry = run("run_key", "u", 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=')
    observation = assess([entry])["observations"][0]
    assert set(observation["signals"]) >= {"lolbin_proxy", "encoded_command"}
    assert observation["grade"] == F.INFERRED


def test_a_quiet_signed_vendor_entry_is_not_accused():
    entry = run("run_key", "OneDrive", "C:\\Program Files\\OneDrive\\OneDrive.exe", signed=True)
    observation = assess([entry])["observations"][0]
    assert observation["signals"] == []
    assert observation["grade"] == F.UNKNOWN
    assert "not evidence of anything" in observation["statement"]


# --- grading and the host trust gap -------------------------------------------------

def test_a_user_writable_unsigned_entry_grades_inferred_from_an_image():
    entry = run("run_key", "upd", "C:\\Users\\bob\\AppData\\Roaming\\upd.exe", signed=False)
    observation = assess([entry])["observations"][0]
    assert observation["grade"] == F.INFERRED
    assert set(observation["signals"]) == {"user_writable_location", "unsigned_binary"}


def test_the_same_entry_from_a_live_host_cannot_be_graded():
    """The subject reporting its own autostart list is a self-report."""
    entry = run("run_key", "upd", "C:\\Users\\bob\\AppData\\Roaming\\upd.exe", signed=False)
    observation = P.assess([entry], basis="live_host")["observations"][0]
    assert observation["grade"] == F.UNKNOWN
    assert "cannot support a persistence finding" in observation["statement"]


def test_a_synthetic_basis_cannot_be_graded_either():
    observation = P.assess([run("run_key", "x", "C:\\Users\\b\\a\\x.exe", signed=False)],
                           basis="synthetic")["observations"][0]
    assert observation["grade"] == F.UNKNOWN


@pytest.mark.parametrize("basis", sorted(P.BASIS_CLASSES))
def test_no_grade_ever_exceeds_the_basis_ceiling(basis):
    result = P.assess([run("run_key", "e", "C:\\Temp\\a.exe", signed=False)], basis=basis)
    order = list(reversed(F.GRADES))
    for observation in result["observations"]:
        if result["ceiling"] is None:
            assert observation["grade"] == F.UNKNOWN
        else:
            assert order.index(observation["grade"]) <= order.index(result["ceiling"])


def test_a_strong_basis_does_not_promote_beyond_the_signals():
    observation = P.assess([run("run_key", "e", "C:\\Temp\\a.exe", signed=False)],
                           basis="attested_image")["observations"][0]
    assert observation["grade"] == F.INFERRED, "a ceiling is a limit, not a target"


# --- coverage: never report clean ---------------------------------------------------

def test_an_empty_snapshot_reports_coverage_not_innocence():
    result = assess([])
    assert result["observations"] == []
    coverage = result["coverage"]
    assert coverage["observed"] == []
    assert "run_key" in coverage["not_observed"]
    assert "not thereby shown to be absent" in coverage["statement"]


def test_reading_one_location_does_not_cover_the_others():
    coverage = assess([run("run_key", "e")])["coverage"]
    assert coverage["observed"] == ["run_key"]
    assert "service" in coverage["not_observed"]


def test_summary_is_deterministic_and_never_claims_clean():
    entries = [run("run_key", "a", "C:\\Temp\\x.exe", signed=False),
               run("run_key", "b", "C:\\Program Files\\y\\y.exe", signed=True)]
    first, second = P.summarise(assess(entries)), P.summarise(assess(entries))
    assert first == second
    assert first["never_claim_clean"] is True
    assert "CLEAN" not in repr(first)


# --- refusals -----------------------------------------------------------------------

def test_an_unknown_mechanism_is_refused():
    with pytest.raises(P.PersistenceError):
        assess([run("magic_persistence", "x")])


def test_an_unknown_basis_is_refused():
    with pytest.raises(P.PersistenceError):
        P.assess([run("run_key", "x")], basis="vibes")


def test_live_capture_needs_an_isolated_attested_path():
    with pytest.raises(S.ScopeError):
        P.assess([run("run_key", "x")], basis="offline_image", scope=S.LIVE_CAPTURE)
    assert P.assess([run("run_key", "x")], basis="offline_image", scope=S.LIVE_CAPTURE,
                    isolated=True, attested=True)["basis"] == "offline_image"


def test_every_observation_says_what_it_could_benignly_be():
    entries = [run("run_key", "e", "C:\\Temp\\a.exe", signed=False),
               run("boot_execute", "b", "autocheck autochk * \\x.sys"),
               run("fileless", "f")]
    for observation in assess(entries)["observations"]:
        assert observation["benign"], observation["mechanism"]
        assert observation["control"], observation["mechanism"]

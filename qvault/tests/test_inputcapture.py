"""Input capture: an observation point is not a severity, and no signals is not a clean bill.

The tests push in both directions - promoting three same-plane signals into corroboration, and letting
a "no findings" result imply safety - because those are the two ways this kind of report goes wrong in
front of a judge.
"""
from __future__ import annotations

import json

import pytest

from qvault.inputcapture import (BENIGN_EXPLANATIONS, COVERAGE, LEVELS, TECHNIQUES, InputCaptureError,
                                 Signal, assess, techniques_by_level)


def sig(technique="keylogging", plane="endpoint_api", source="edr"):
    return Signal(technique, plane, source)


def test_an_empty_case_is_unknown_and_explains_why():
    verdict = assess([])
    assert verdict.grade == "UNKNOWN"
    assert "not absence of capture" in verdict.caveat


def test_level_four_cannot_be_observed_from_the_host():
    meta = TECHNIQUES["external_interception"]
    assert meta["level"] == 4 and meta["planes"] == set()
    with pytest.raises(InputCaptureError, match="cannot observe"):
        assess([sig("external_interception", "process")])
    assert "unobservable" in COVERAGE[4]


def test_three_signals_from_one_plane_are_one_observation():
    verdict = assess([sig(), sig(source="av"), sig(source="agent")])
    assert verdict.techniques[0]["planes"] == ["endpoint_api"]
    assert verdict.techniques[0]["grade"] == "INFERRED"


def test_two_planes_corroborate_only_once_the_innocent_explanation_is_excluded():
    signals = [sig("driver_keylogger", "driver"), sig("driver_keylogger", "registry")]
    capped = assess(signals)
    assert capped.techniques[0]["grade"] == "INFERRED"
    assert capped.techniques[0]["exclude_first"] in BENIGN_EXPLANATIONS
    # Excluding one of four innocent categories is not enough: a key remapper is still unexcluded.
    partial = assess(signals, exclusions={"vendor_input_driver"})
    assert partial.techniques[0]["grade"] == "INFERRED"
    clean = assess(signals, exclusions=set(BENIGN_EXPLANATIONS))
    assert clean.techniques[0]["grade"] == "CORROBORATED"


def test_confirmed_is_never_returned():
    verdict = assess([sig("keylogging", "endpoint_api"), sig("keylogging", "device_access")],
                     exclusions=set(BENIGN_EXPLANATIONS))
    assert verdict.grade == "CORROBORATED"
    assert "CONFIRMED" not in json.dumps({"g": verdict.grade,
                                          "t": [t["grade"] for t in verdict.techniques]})


def test_a_level_one_technique_can_outrank_a_level_three_one_on_impact():
    verdict = assess([sig("session_theft", "endpoint_api"), sig("driver_keylogger", "driver")],
                     exclusions=set(BENIGN_EXPLANATIONS))
    by_name = {t["technique"]: t for t in verdict.techniques}
    assert by_name["session_theft"]["level"] == 1
    assert by_name["session_theft"]["impact"] == "high"
    assert by_name["driver_keylogger"]["level"] == 3
    assert by_name["driver_keylogger"]["impact"] == "high"


def test_the_overall_grade_is_the_weakest_technique():
    verdict = assess([sig("session_theft", "endpoint_api"), sig("session_theft", "network"),
                      sig("keylogging", "endpoint_api")], exclusions=set(BENIGN_EXPLANATIONS))
    assert verdict.grade == "INFERRED"


@pytest.mark.parametrize("bad", [
    Signal("telepathy", "process", "x"),
    Signal("keylogging", "astrology", "x"),
    Signal("keylogging", "network", "x"),      # a plane that cannot see keylogging
])
def test_unknowns_and_impossible_planes_are_refused(bad):
    with pytest.raises(InputCaptureError):
        assess([bad])


def test_an_invented_benign_exclusion_is_refused():
    with pytest.raises(InputCaptureError, match="benign"):
        assess([sig()], exclusions={"it_was_fine"})


def test_coverage_is_stated_for_every_level():
    coverage = assess([]).coverage
    assert set(coverage) == set(LEVELS) == {1, 2, 3, 4}
    assert coverage[2].startswith("observable")
    assert coverage[1].startswith("partial")


def test_the_limitations_name_the_trap():
    text = " ".join(assess([]).limitations)
    assert "not a severity" in text
    assert "cannot confirm" in text


def test_every_technique_has_a_level_and_every_level_has_a_technique():
    grouped = techniques_by_level()
    assert sum(len(v) for v in grouped.values()) == len(TECHNIQUES)
    assert grouped[4] == ["external_interception"]


def test_no_output_word_claims_cleanliness():
    payload = json.dumps({"grade": assess([]).grade, "caveat": assess([]).caveat})
    assert "clean" not in payload.lower()

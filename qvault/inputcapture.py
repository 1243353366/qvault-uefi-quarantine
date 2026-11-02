"""
qvault.inputcapture
===================

Input capture, graded by where it observes rather than by how impressive it sounds.

The four tiers describe an **observation point**, not a sophistication ranking and not a severity
ranking. A browser-side credential thief sits at level 1 and routinely does more damage than a crude
kernel keylogger at level 3, because a session cookie is worth more than a paragraph of someone's
typing. Severity therefore comes from *what is captured*, on its own axis, and the two are reported
separately so neither can be mistaken for the other.

What this module will not say
-----------------------------
* **Never "clean".** No signals observed is `UNKNOWN`, not absence of capture. Level 4 - physical
  interception or compromised firmware - produces no endpoint telemetry at all, so a host cannot
  testify about it even in principle.
* **Never `CONFIRMED`.** Passive endpoint telemetry can corroborate; it cannot confirm. Confirmation
  needs ground truth from outside the subject, which is the same reason the lab doctrine wants an
  external SPI read rather than a software tool on the suspect host.
* **Never a verdict from one plane.** Three signals from the endpoint API plane are one observation
  seen three times. `CORROBORATED` requires two distinct planes.
* **Never ignore the innocent explanation.** Accessibility software, keyboard utilities and
  remote-support tools produce these signals legitimately. Until the analyst records an exclusion,
  the grade is capped and the note names the tool category to rule out.

Credential and session theft are first-class here, not an afterthought: keylogging is one input-capture
technique among several, and usually not the cheapest one to run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Observation point. Not severity, not sophistication - say so wherever these are shown.
LEVELS = {
    1: ("application", "browser forms, credential APIs, clipboard, GUI text, session tokens"),
    2: ("os", "keyboard hooks and input APIs used by ordinary processes"),
    3: ("privileged", "drivers, kernel modules, deeper operating-system compromise"),
    4: ("external", "physical interception, or compromised hardware or firmware"),
}

#: Distinct telemetry planes. Two signals from one plane are one observation.
PLANES = frozenset({
    "endpoint_api", "device_access", "process", "driver", "registry", "network", "permission",
})

#: Collection mechanisms, their level, the planes that can see them, and what they cost the victim.
#: `impact` is a separate axis from `level` on purpose.
TECHNIQUES = {
    "form_grabbing":            {"level": 1, "planes": {"endpoint_api", "network"}, "impact": "high"},
    "credential_api_hooking":   {"level": 1, "planes": {"endpoint_api", "process"}, "impact": "high"},
    "session_theft":            {"level": 1, "planes": {"endpoint_api", "network"}, "impact": "high"},
    "clipboard_monitoring":     {"level": 1, "planes": {"endpoint_api", "process"}, "impact": "medium"},
    "gui_capture":              {"level": 1, "planes": {"endpoint_api", "permission"}, "impact": "medium"},
    "keylogging":               {"level": 2, "planes": {"endpoint_api", "device_access", "process"},
                                 "impact": "medium"},
    "driver_keylogger":         {"level": 3, "planes": {"driver", "registry", "process"},
                                 "impact": "high"},
    "external_interception":    {"level": 4, "planes": set(), "impact": "high"},
}

#: Innocent explanations that legitimately produce these signals. Each must be excluded on the record
#: before a technique can be corroborated.
BENIGN_EXPLANATIONS = {
    "accessibility_tool": "screen readers and switch access read input and screen content by design",
    "keyboard_utility": "macro, remapping and hotkey tools hook the keyboard API",
    "remote_support": "support and remote-desktop agents capture input and screen by design",
    "vendor_input_driver": "a signed vendor driver may legitimately own the input stack",
}

#: Per-level coverage of a host-resident observer, stated up front so a report cannot imply more.
COVERAGE = {
    1: "partial: only visible if the application or a browser extension reports it",
    2: "observable: OS-level input APIs and the processes using them",
    3: "partial: a driver install is visible; a kernel-resident hook may not be",
    4: "unobservable from the host: needs external instrumentation",
}

_GRADE_RANK = {"CONFIRMED": 0, "CORROBORATED": 1, "INFERRED": 2, "HYPOTHESIS": 3, "UNKNOWN": 4}


class InputCaptureError(RuntimeError):
    """Unknown technique, plane or signal. No silent defaults."""


@dataclass(frozen=True)
class Signal:
    technique: str
    plane: str
    source: str
    note: str = ""


@dataclass
class Verdict:
    techniques: list[dict] = field(default_factory=list)
    grade: str = "UNKNOWN"
    coverage: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    caveat: str = ""


def assess(signals: list[Signal], *, exclusions: set[str] | None = None) -> Verdict:
    """Grade observed signals. `exclusions` names benign explanations the analyst has ruled out."""
    exclusions = exclusions or set()
    for name in exclusions:
        if name not in BENIGN_EXPLANATIONS:
            raise InputCaptureError(f"unknown benign explanation {name!r}")

    by_technique: dict[str, list[Signal]] = {}
    for sig in signals:
        if sig.technique not in TECHNIQUES:
            raise InputCaptureError(f"unknown technique {sig.technique!r}")
        if sig.plane not in PLANES:
            raise InputCaptureError(f"unknown telemetry plane {sig.plane!r}")
        if sig.plane not in TECHNIQUES[sig.technique]["planes"]:
            raise InputCaptureError(
                f"plane {sig.plane!r} cannot observe {sig.technique!r}")
        by_technique.setdefault(sig.technique, []).append(sig)

    verdict = Verdict(coverage={lvl: COVERAGE[lvl] for lvl in LEVELS})

    for technique, seen in sorted(by_technique.items()):
        meta = TECHNIQUES[technique]
        planes = {s.plane for s in seen}
        # Every innocent category has to be excluded on the record, not just the convenient one: a
        # report that rules out "remote support" and stops has not ruled out a key remapper.
        benign = [b for b in BENIGN_EXPLANATIONS if b not in exclusions]
        if len(planes) >= 2:
            grade = "CORROBORATED"
        else:
            grade = "INFERRED"
        if benign:
            # An unexcluded innocent explanation caps the grade: correlation is not causation.
            if _GRADE_RANK[grade] < _GRADE_RANK["INFERRED"]:
                grade = "INFERRED"
        verdict.techniques.append({
            "technique": technique,
            "level": meta["level"],
            "level_name": LEVELS[meta["level"]][0],
            "impact": meta["impact"],
            "planes": sorted(planes),
            "signals": len(seen),
            "grade": grade,
            "exclude_first": benign[0] if benign else None,
        })

    if verdict.techniques:
        # Weakest, not strongest: `min` on the rank picks the *most* confident technique, so a case
        # with one corroborated technique and one inferred one reported CORROBORATED overall.
        verdict.grade = max((t["grade"] for t in verdict.techniques), key=_GRADE_RANK.get)
    else:
        verdict.grade = "UNKNOWN"
        verdict.caveat = ("no signals observed is not absence of capture: level 4 produces no "
                          "endpoint telemetry, and level 1 depends on the application reporting")

    verdict.limitations = [
        "a level is an observation point, not a severity: level 1 session theft outranks a level 3 keylogger",
        "passive telemetry corroborates; it cannot confirm - confirmation needs ground truth from outside the subject",
        "level 4 is out of scope for host detection: use external instrumentation",
        f"{len(BENIGN_EXPLANATIONS)} innocent explanations must be excluded on the record first",
    ]
    return verdict


def techniques_by_level() -> dict[int, list[str]]:
    out: dict[int, list[str]] = {lvl: [] for lvl in LEVELS}
    for name, meta in TECHNIQUES.items():
        out[meta["level"]].append(name)
    return out

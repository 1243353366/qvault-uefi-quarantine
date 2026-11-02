#!/usr/bin/env python3
"""Render report/INPUT_CAPTURE.md from qvault.inputcapture, so the tables cannot drift."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault.inputcapture import (BENIGN_EXPLANATIONS, COVERAGE, LEVELS, TECHNIQUES,
                                 techniques_by_level)  # noqa: E402

OUT = ROOT / "report" / "INPUT_CAPTURE.md"


def render() -> str:
    o = ["# Input capture: four tiers, and why the tier is not the danger\n\n"]
    o.append(f"Release **{__version__}**. Module `qvault/inputcapture.py`, tests "
             "`qvault/tests/test_inputcapture.py`.\n\n")
    o.append("A collection mechanism can only capture what its observation point can see. That makes the "
             "observation point the useful axis for classifying input capture, and it makes **severity a "
             "separate axis**: a browser-side session thief at level 1 routinely inflicts more damage "
             "than a crude kernel keylogger at level 3, because an authenticated cookie is worth more "
             "than a paragraph of typing. This page keeps the two apart everywhere.\n\n")

    o.append("## The four tiers\n\n")
    o.append("| Level | Observation point | What it sees | Coverage from a host-resident observer |\n")
    o.append("|---|---|---|---|\n")
    for level, (name, contents) in LEVELS.items():
        o.append(f"| {level} | {name} | {contents} | {COVERAGE[level]} |\n")
    o.append("\nLevel 4 is listed rather than quietly omitted. Anything that reads input before it reaches "
             "the machine - or inside compromised firmware - leaves no endpoint telemetry, so this project "
             "cannot detect it and does not pretend to. Confirming it needs external instrumentation, the "
             "same reasoning that makes an off-host SPI read the ground truth in the acquisition doctrine.\n\n")

    o.append("## Techniques, by observation point\n\n")
    o.append("| Technique | Level | Planes that can see it | Impact |\n|---|---|---|---|\n")
    for name, meta in TECHNIQUES.items():
        planes = ", ".join(sorted(meta["planes"])) or "none: no endpoint signal exists"
        o.append(f"| `{name}` | {meta['level']} | {planes} | {meta['impact']} |\n")
    o.append("\nKeylogging is one row, not the category. Form grabbing, credential-API hooking, session "
             "theft and clipboard monitoring are cheaper to run and often worth more, which is why they are "
             "first-class here.\n\n")

    o.append("## Grading rules\n\n")
    o.append("| Rule | Consequence |\n|---|---|\n")
    o.append("| Two distinct telemetry planes | `CORROBORATED`; one plane, however many signals, is `INFERRED` |\n")
    o.append("| Innocent explanations | every listed category must be excluded on the record before "
             "corroboration; excluding the convenient one is not enough |\n")
    o.append("| Confirmation | `CONFIRMED` is never returned: passive telemetry corroborates, it cannot confirm |\n")
    o.append("| No findings | `UNKNOWN`, never clean; the caveat names level 4 and application dependence |\n")
    o.append("| Aggregation | the case grade is the **weakest** technique, not the strongest |\n")
    o.append("\n")

    o.append("## The innocent explanations that must be excluded first\n\n")
    o.append("| Category | Why it produces the same signals |\n|---|---|\n")
    for name, why in BENIGN_EXPLANATIONS.items():
        o.append(f"| `{name}` | {why} |\n")
    o.append("\nAn API hook is not a finding. Accessibility software reads input and screen content by "
             "design; macro and remapping tools hook the keyboard; remote-support agents do both. The "
             "report asks the analyst to exclude each category, and records that they did.\n\n")

    o.append("## Signals worth correlating\n\n")
    o.append("Per MITRE ATT&CK's input-capture techniques, the signals a defender can actually collect are: "
             "keyboard-monitoring API activity from a process with no user interface, non-UI processes "
             "touching input devices, unauthorised driver installation, suspicious registry modification of "
             "input handlers, unexpected input-monitoring permission grants on macOS, and correlation "
             "between input access, process creation and unusual outbound traffic. Each maps to a plane in "
             "the table above, and the plane, not the count, decides corroboration.\n\n")

    o.append("## A bug this module found in itself\n\n")
    o.append("The first version computed the case grade with `min` over grade ranks. Because the ranks run "
             "from `CONFIRMED` at zero, that returned the **strongest** technique: a case with one "
             "corroborated and one merely inferred technique reported `CORROBORATED` overall. A test that "
             "expected the weakest grade caught it. This is the specific error a report cannot afford, "
             "since it upgrades a claim by arithmetic rather than evidence.\n\n")

    o.append("## Defensibility\n\n")
    o.append("What an examiner can rely on: the tier is an observation point with a stated coverage; the "
             "impact axis is separate and cannot be inflated by the tier; corroboration needs two planes; "
             "innocent categories are enumerated and must be excluded on the record; the case grade cannot "
             "exceed the weakest technique; `CONFIRMED` and \"clean\" are unreachable, including for an "
             "empty case.\n\n")
    o.append("What is not attempted: detection of level 4, and detection of anything on a host whose kernel "
             "is already compromised. `qvault/report/THREAT_INTEL.md` covers how such a finding is packaged "
             "for filing, with hash-verified artefacts and a required competing explanation.\n\n")

    o.append("## Techniques per tier\n\n")
    grouped = techniques_by_level()
    for level, names in sorted(grouped.items()):
        o.append(f"- **Level {level}** ({LEVELS[level][0]}): " +
                 (", ".join(f"`{n}`" for n in names) if names else "none recorded") + "\n")
    return "".join(o)


def main() -> int:
    OUT.write_text(tables.align(render()))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

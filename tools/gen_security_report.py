#!/usr/bin/env python3
"""Render report/SECURITY_REPORT.md: the point-in-time security report for this release.

Generated, not hand-written, because a security report that drifts from the code it describes is
worse than none: the reader cannot tell which sentence is still true. Every number here is read
from the tree at generation time, and gate G12 keeps the page and the source in step.
"""
from __future__ import annotations

import collections
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import gates  # noqa: E402
import tables  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault import denial as D  # noqa: E402
from qvault import findings as F  # noqa: E402

OUT = ROOT / "report" / "SECURITY_REPORT.md"
LEDGER = ROOT / "report" / "CLAIMS_LEDGER.csv"

#: Findings that are open at this release. Each is a real limit of the system, graded, with the
#: observation that would close it. None of them is a bug being worked around quietly.
OPEN_FINDINGS = (
    ("Host trust gap",
     "A1",
     F.CONFIRMED,
     "Every control that runs on the target is void once the kernel or the boot chain below it is "
     "compromised, which is exactly the case a bootkit creates.",
     "A control exercised on a host with a malicious kernel that still reports success."),
    ("Self-scan cannot establish its own integrity",
     "A5",
     F.CONFIRMED,
     "A tool that reads its own stack through that stack cannot prove the reading. Self-scan "
     "detects accidental damage and casual tampering, not a capable adversary.",
     "A self-scan passing on a host where the tool's own binary was modified."),
    ("No identity binding for dual control",
     "A7",
     F.CONFIRMED,
     "Two approvals are required and both are recorded, but an approver name is not bound to a "
     "verified principal, so one person with two keys satisfies the check.",
     "A documented case where one operator produced both approvals."),
    ("Hardware protection state in emulation",
     "H1",
     F.HYPOTHESIS,
     "OVMF has no SPI controller registers, so a write-protected flash state observed in QEMU is "
     "a property of the emulator, not of firmware.",
     "The same read on real hardware disagreeing with the emulated result."),
    ("Protection state reading methods",
     "H4",
     F.HYPOTHESIS,
     "Software readers of SPI protection bits run on the platform they are measuring; a compromised "
     "firmware can report protected while unprotected.",
     "An out-of-band programmer reading protection bits that contradict the software reader."),
    ("Retroactive encryption has a boundary",
     "D2",
     F.CORROBORATED,
     "Encrypting evidence denies access from the moment the key is withheld. It does not undo a key "
     "or a plaintext copy taken before that moment, and it does not touch a bootkit that needs no "
     "payload to decrypt.",
     "Evidence recovered from a snapshot taken before the key was withheld."),
)

#: Sentences a security report of this kind must never contain. Absence of evidence is not evidence.
FORBIDDEN_CLAIMS = (
    "is malware-free",
    "proves the absence",
    "guarantees",
    "cannot be compromised",
    "100% detection",
)


def ledger_census() -> tuple[dict, dict, int]:
    rows = list(csv.DictReader(LEDGER.open()))
    tags = collections.Counter(r["tag"] for r in rows)
    verification = collections.Counter(r["verification"] for r in rows)
    return dict(tags), dict(verification), len(rows)


def render() -> str:
    tags, verification, total = ledger_census()
    unverified = verification.get("none", 0)
    citations = (ROOT / "CITATIONS.md").read_text()
    sources = citations.split("sources.", 1)[0].strip().split()[-1]

    out = [f"# Security report - qvault {__version__}\n\n"]
    out.append(
        f"This is the point-in-time security report for release **{__version__}**. It describes what\n"
        "the system enforces, what it can prove about itself, and what remains open. It is generated\n"
        "from the tree it describes: the counts, the gate list and the grade census are read at build\n"
        "time, so a stale claim fails the build rather than sitting in a document.\n\n")
    out.append(
        "> **Scope.** Defensive firmware forensics: acquisition, quarantine, evidence grading and\n"
        "> containment for UEFI-resident malware. No live host, no real SPI flash and no physical\n"
        "> programmer were available, so every hardware-plane statement is graded accordingly and\n"
        "> gathered in [the limitations page](limitations.html).\n\n")

    out.append("## 1. What was verified, and how\n\n")
    out.append(
        f"The release passes **{len(gates.GATES)} gates**, each of which refuses the push that would\n"
        "break it. The gates are not a checklist; each one exists because something went wrong first:\n\n")
    out.append("| Gate | Checks |\n|---|---|\n")
    for gid, name, _fn in gates.GATES:
        out.append(f"| {gid} | {name} |\n")
    out.append(
        "\nThe unit suite is run by G1 and the end-to-end lifecycle by G2. CI repeats the whole set on\n"
        "two Python versions alongside a wheel install outside the checkout, so the evidence is\n"
        "reproducible without trusting the author's machine.\n\n")

    out.append("## 2. Evidence base\n\n")
    out.append(
        f"The claims ledger holds **{total}** claims. Every one carries a source, a locator, a tag and\n"
        "a falsifier. The census at this release:\n\n")
    out.append("| Tag | Claims |\n|---|---|\n")
    for grade in F.GRADES:
        out.append(f"| {grade} | {tags.get(grade, 0)} |\n")
    out.append("\n")
    out.append("| Verification method | Claims |\n|---|---|\n")
    for method, count in sorted(verification.items()):
        out.append(f"| {method} | {count} |\n")
    out.append("\n")
    out.append(
        f"**{unverified} claims carry no independent verification.** They are cited to a source\n"
        "and graded no higher than the source supports, and they are counted here rather than\n"
        "rounded away: a report that only lists verified claims is a report about the easy half.\n\n")
    out.append(f"{sources} sources are catalogued and individually linked on the\n"
               "[citations page](citations.html).\n\n")

    out.append("## 3. What the system enforces\n\n")
    out.append("Three denial postures, each recorded with the condition that ends it:\n\n")
    out.append("| Posture | Denies | Ceiling on a good plane | Ends when |\n|---|---|---|---|\n")
    for posture in D.POSTURES:
        ceiling = D.assess(posture.name, plane="hardware", corroborating_evidence=3,
                           enforced_by_target=False)["grade"]
        out.append(f"| `{posture.name}` | {posture.denies} | {ceiling} | {posture.restored_when} |\n")
    out.append(
        "\nNo denial claim reaches CONFIRMED and gate G17 enforces that. Inability is inferred from\n"
        "the absence of a success, and this project does not promote absence.\n\n")
    out.append("The full model, including what each posture does not do, is\n"
               "[the denial model page](denial-model.html).\n\n")

    out.append("## 4. Open findings\n\n")
    out.append("These are live limits, not historical notes. Each carries its grade and the observation\n"
               "that would close it.\n\n")
    for title, ref, grade, body, falsifier in OPEN_FINDINGS:
        out.append(f"### {ref} - {title} ({grade})\n\n")
        out.append(f"{body}\n\n")
        out.append(f"**Would be closed by:** {falsifier}\n\n")

    out.append("## 5. What this report does not claim\n\n")
    out.append("It does not claim any host is clean, any implant is absent, or any hardware protection\n"
               "is active on real firmware. Absence of a finding is not evidence of absence: the\n"
               "system distinguishes *no finding* from *no observation*, and only the second is a gap\n"
               "in the evidence.\n\n")
    out.append("It also does not claim the denial postures are independent of each other. Three controls\n"
               "enforced by one authority are one control, and the composition table in the denial\n"
               "model says so.\n\n")

    out.append("## 6. Reproducing this report\n\n")
    out.append("```bash\ngit clone https://github.com/1243353366/qvault-uefi-quarantine\n"
               "cd qvault-uefi-quarantine\n"
               "pip install -r requirements-dev.txt\npython -m pytest qvault/tests -q\n"
               "python3 tools/gates.py\npython3 tools/gen_security_report.py\n```\n\n")
    out.append(f"Release artifact: `v{__version__}`. The gate list, the census and the posture ceilings\n"
               "above are regenerated from the code at every build.\n")
    return "".join(out)


def assert_no_overclaim(text: str) -> None:
    lowered = text.lower()
    for phrase in FORBIDDEN_CLAIMS:
        if phrase in lowered:
            raise ValueError(f"the security report contains a forbidden claim: {phrase!r}")


def main() -> int:
    body = render()
    assert_no_overclaim(body)
    OUT.write_text(tables.align(body))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

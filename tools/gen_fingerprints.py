#!/usr/bin/env python3
"""Generate report/FINGERPRINTS.md from the catalogue, so the document cannot drift
away from the code that implements it.

Run: python3 tools/gen_fingerprints.py
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qvault import fingerprints as P  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "report", "FINGERPRINTS.md")

HEADER = """# Published-source fingerprints and their defensive inversion

Generated from `qvault/fingerprints.py` by `tools/gen_fingerprints.py`. Do not edit by hand.

## What this is not

No LoJax, MoonBounce or BlackLotus sample was handled to produce this catalogue. Nothing in
this repository contains malware, and no entry below is primary-sourced. Each one comes from
published analysis, carries that source, and is graded accordingly. `assert_catalogue_integrity()`
**refuses** a `CONFIRMED` grade here, because a claim of primary analysis would be false.

## Why a string match is only a lead

The same bytes appear in a compromised firmware image, in an EDR rule, and in the notes of
anyone reading both. A textual match therefore caps at `INFERRED`, and every entry carries the
benign explanation that most often produces it. `LOJAX-1` is the clearest case: `rpcnetp` is
also the legitimate Absolute/Computrace anti-theft agent, so its presence is normal on a great
many OEM machines. Alerting on it without corroboration is the textbook false positive.

## The catalogue

"""

COUNTER = """
## Defensive inversion

For each mechanism the families use, the control that defeats it. This is the useful
direction: the mechanism is published, so the defence can be built without reproducing the
attack.

"""

FOOTER = """
## Detection discipline

- A lead is an `Observation`, never a `Finding`. `fingerprints.observations()` returns
  observations, and a human supplies the benign-explanation adjudication that promotes one.
- Hits never claim identification. Family attribution requires the two-independent-upstream
  rule from `limitations.intel_trust`.
- Firmware claims need out-of-band evidence: an unnamed section found by an OS-mediated read
  is a lead about a possibly-forged blob, not firmware integrity (see `firmware_integrity`).
"""


def main() -> None:
    import sys
    check = "--check" in sys.argv
    P.assert_catalogue_integrity()
    lines = [HEADER]

    for family in P.FAMILIES:
        lines.append(f"### {family}\n\n")
        lines.append("| id | kind | matched on | grade | benign reading to exclude | "
                     "hostile when | countermeasure |\n")
        lines.append("|---|---|---|---|---|---|---|\n")
        for fp in P.by_family(family):
            lines.append(
                f"| `{fp.id}` | {fp.kind} | `{fp.value}` | {fp.grade} | {fp.benign} | "
                f"{fp.hostile_when} | {fp.countermeasure} |\n"
            )
        lines.append("\n**Sources.**\n\n")
        seen = []
        for fp in P.by_family(family):
            if fp.source not in seen:
                seen.append(fp.source)
        for src in seen:
            lines.append(f"- {src}\n")
        lines.append("\n")

    lines.append(COUNTER)
    for family in P.FAMILIES:
        lines.append(f"### {family}\n\n")
        lines.append("| mechanism | control | implemented in |\n|---|---|---|\n")
        for item in P.defender_inversion(family):
            lines.append(f"| {item['mechanism']} | {item['control']} | `{item['module']}` |\n")
        lines.append("\n")

    lines.append(FOOTER)
    rendered = "".join(lines)
    count = sum(len(P.by_family(f)) for f in P.FAMILIES)

    if check:
        current = pathlib.Path(OUT).read_text(encoding="utf-8") if pathlib.Path(OUT).exists() else ""
        if current != rendered:
            print(f"{OUT} differs from what the code generates")
            raise SystemExit(1)
        print(f"{OUT} matches the code ({count} fingerprints)")
        return

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(rendered)
    print(f"wrote {OUT} ({count} fingerprints)")


if __name__ == "__main__":
    main()

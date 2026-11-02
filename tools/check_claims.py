#!/usr/bin/env python3
"""
check_claims.py — enforce rule R3 on the claims ledger.

Any technical conclusion in this project must have:
  * a source (bibliography number, or an explicit "author reasoning" marker),
  * a confidence tag from the fixed vocabulary,
  * a verification status,
  * a falsifier, and
  * a section reference that actually exists in the report.

Run:  python tools/check_claims.py
Exit: 0 clean, 1 violations.

The point is not ceremony. A claim with no falsifier cannot be attacked, and a
claim pointing at a section that does not exist cannot be checked by a reader.
"""

from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "report" / "CLAIMS_LEDGER.csv"
REPORT = ROOT / "report" / "UEFI_Malware_Deep_Dive_Report.md"

COLUMNS = ["id", "section", "claim", "bib", "locator", "tag", "verification", "falsifier"]

TAGS = {"CONFIRMED", "CORROBORATED", "INFERRED", "HYPOTHESIS", "UNKNOWN"}
VERIFICATION = {"none", "partial", "independent"}
# Claims that assert something about the outside world need a real citation.
NEEDS_CITATION = {"CONFIRMED", "CORROBORATED", "UNKNOWN"}
MIN_FALSIFIER = 20


def report_sections() -> set[str]:
    """Collect section numbers that exist as headings in the report."""
    found = set()
    if not REPORT.exists():
        return found
    for line in REPORT.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^#{2,3}\s+(\d+(?:\.\d+)?)[\.\s]", line)
        if m:
            found.add(m.group(1))
    return found


def _bibliography_max(report_text: str) -> int:
    """Highest numbered bibliography entry actually present in the report."""
    numbers = [int(m) for m in re.findall(r"^(\d+)\. ", report_text, flags=re.MULTILINE)]
    return max(numbers) if numbers else 0


def main() -> int:
    if not LEDGER.exists():
        print(f"FAIL: ledger not found at {LEDGER}")
        return 1

    sections = report_sections()
    errors: list[str] = []
    bib_max = _bibliography_max(REPORT.read_text())
    tag_counts: dict[str, int] = {}
    ver_counts: dict[str, int] = {}

    with LEDGER.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            print(f"FAIL: header is {reader.fieldnames}, expected {COLUMNS}")
            return 1
        rows = list(reader)

    for row in rows:
        cid = row["id"]

        if row["tag"] not in TAGS:
            errors.append(f"{cid}: invalid tag {row['tag']!r}")
        if row["verification"] not in VERIFICATION:
            errors.append(f"{cid}: invalid verification {row['verification']!r}")
        tag_counts[row["tag"]] = tag_counts.get(row["tag"], 0) + 1
        ver_counts[row["verification"]] = ver_counts.get(row["verification"], 0) + 1

        if len(row["falsifier"].strip()) < MIN_FALSIFIER:
            errors.append(f"{cid}: falsifier too short (must be attackable)")

        if row["section"] not in sections:
            errors.append(f"{cid}: section {row['section']!r} has no heading in the report")

        bib = row["bib"].strip()
        # Claims about this repository's own code cite the code and its tests,
        # not the external bibliography.
        if row["verification"] == "independent" and not bib:
            bib = "n/a"
        if row["tag"] in NEEDS_CITATION and bib not in ("n/a",) and not bib.isdigit():
            errors.append(f"{cid}: {row['tag']} requires a bibliography number, got {bib!r}")
        if bib and bib != "n/a" and not bib.isdigit():
            errors.append(f"{cid}: bib {bib!r} is not numeric")
        if bib.isdigit() and not (1 <= int(bib) <= bib_max):
            errors.append(f"{cid}: bib {bib} outside expected bibliography range")
        if not bib and "reasoning" not in row["locator"].lower():
            errors.append(f"{cid}: no citation and not marked as author reasoning")

        # Only this repository's own behaviour may claim independent verification.
        if row["verification"] == "independent":
            if row["tag"] not in {"CONFIRMED", "INFERRED"}:
                errors.append(
                    f"{cid}: independent verification requires tag CONFIRMED or INFERRED"
                )
            if not re.search(r"qvault|test", row["locator"], re.I):
                errors.append(f"{cid}: independent verification only for qvault/tests claims")

        # Nothing here may claim first-hand verification of the malware families.
        if row["section"].split(".")[0] in {"2", "3", "4"} and row["verification"] != "none":
            errors.append(
                f"{cid}: family claims are secondary-source only; verification must be 'none'"
            )

    print(f"ledger: {LEDGER.relative_to(ROOT)}  ({len(rows)} claims)")
    print(f"sections found in report: {len(sections)}")
    print("tags:        " + ", ".join(f"{k}={v}" for k, v in sorted(tag_counts.items())))
    print("verification:" + ", ".join(f" {k}={v}" for k, v in sorted(ver_counts.items())))

    if errors:
        print(f"\n{len(errors)} violation(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("\nOK: every claim has a source, a tag, a status and a falsifier.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Apply rules F1-F5 to findings produced by other tools.

    python tools/check_findings.py findings.json [findings2.json ...]

Accepts a single finding object, a list of them, or an object with a "findings"
array (a DeviceAssessment). Exits non-zero if any violation is found.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qvault.findings import audit_finding  # noqa: E402


def iter_findings(doc):
    if isinstance(doc, list):
        for item in doc:
            yield from iter_findings(item)
    elif isinstance(doc, dict):
        if "findings" in doc and isinstance(doc["findings"], list):
            yield from doc["findings"]
        elif "observation" in doc or "identifier" in doc:
            yield doc


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    total = 0
    for path in argv[1:]:
        try:
            doc = json.loads(Path(path).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{path}: unreadable ({exc})")
            total += 1
            continue
        for finding in iter_findings(doc):
            for v in audit_finding(finding):
                total += 1
                print(f"{path}: [{v['rule']}] {v['identifier']}: {v['why']}")
    if total:
        print(f"\n{total} violation(s)")
        return 1
    print("OK: no violations of F1-F5")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

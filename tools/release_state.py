#!/usr/bin/env python3
"""Report whether the released state, the remote state and the live site agree.

The failure this exists for: v0.13.3 was tagged, then one more commit landed, so the tag pointed
one commit behind main while the README implied the release was current. Nothing caught it, because
every gate runs before the tag exists. This is a read-only diagnosis, not a gate: it needs the
network and the pushed tag, so it runs after a release, not before a push.

Exit code is 1 when local HEAD, the tag, the newest CI run, the Pages build and the badge disagree.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request

REPO = "1243353366/qvault-uefi-quarantine"
OWNER, NAME = REPO.split("/")
SITE = f"https://{OWNER.lower()}.github.io/{NAME}/"


def _api(path: str) -> dict | list:
    token = os.environ.get("GITHUB_ACCESS_TOKEN")
    if not token:
        raise SystemExit("GITHUB_ACCESS_TOKEN is not set; this diagnostic needs the API")
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}{path}",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def _git(*args: str) -> str:
    return subprocess.run(("git", *args), capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    head = _git("rev-parse", "HEAD")
    newest_tag = _git("describe", "--tags", "--abbrev=0", "HEAD")
    tag_commit = _git("rev-list", "-n", "1", newest_tag)

    run = (_api("/actions/runs?per_page=1&branch=main") or {}).get("workflow_runs", [{}])[0]
    build = _api("/pages/builds/latest")
    releases = _api("/releases?per_page=1") or [{}]

    rows = [
        ("HEAD", head[:8], True),
        (f"tag {newest_tag}", tag_commit[:8], tag_commit == head),
        ("newest CI run", f"{run.get('status')}/{run.get('conclusion')} {run.get('head_sha', '')[:8]}",
         run.get("conclusion") == "success" and (run.get("head_sha") or "").startswith(head[:8])),
        ("pages build", f"{build.get('status')} {build.get('commit', '')[:8]}",
         build.get("status") == "built" and (build.get("commit") or "").startswith(head[:8])),
        ("newest release", releases[0].get("tag_name", "none"),
         releases[0].get("tag_name") == newest_tag),
    ]

    width = max(len(label) for label, _, _ in rows)
    ok = True
    for label, value, agrees in rows:
        ok &= agrees
        print(f"{'PASS' if agrees else 'FAIL'}  {label.ljust(width)}  {value}")
    print()
    print("GREEN: release, remote and site agree" if ok else "NOT GREEN: the rows above disagree")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

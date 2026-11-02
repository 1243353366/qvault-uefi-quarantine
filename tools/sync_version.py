#!/usr/bin/env python3
"""The version has exactly one source: `qvault/__init__.py`.

Anything that prints the *current* version must not carry its own copy of the string, because
a copy is a fact that goes stale silently. The README already did: it advertised 0.5.0 while
the package was at 0.13.0, and no gate noticed because no gate compared them.

Deliberately exempt, with reasons:
  - `CHANGELOG.md` and git tags record *past* versions; rewriting them would falsify history.
  - `vendor/zbtriage/__init__.py` is an upstream release number, not ours.
  - `docs/` is generated from these sources and is checked by gate G12.
  - `requirements-lock.txt` pins dependency versions, which are not ours to single-source.

Usage:
  python3 tools/sync_version.py --check    # gate: exit 1 on any disagreement
  python3 tools/sync_version.py --write     # make the copies agree with the source
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "qvault" / "__init__.py"
VERSION_RE = r"\d+\.\d+\.\d+"

#: Files that state the current version, with the pattern holding it in group 1.
TARGETS = [
    ("README.md", rf"\*\*Version ({VERSION_RE})\*\*"),
]

EXEMPT = {
    "CHANGELOG.md": "records past releases; rewriting it would falsify history",
    "vendor/": "upstream release number, pinned and audited separately",
    "docs/": "generated; covered by gate G12",
    "requirements-lock.txt": "dependency pins, not this project's version",
}


def source_version() -> str:
    match = re.search(rf'^__version__ = "({VERSION_RE})"$',
                      SOURCE.read_text(), re.MULTILINE)
    if not match:
        raise SystemExit(f"cannot read __version__ from {SOURCE.relative_to(ROOT)}")
    return match.group(1)


def claimed() -> list[tuple[str, str]]:
    """(file, version claimed there) for every place that states the current version."""
    found = []
    for name, pattern in TARGETS:
        path = ROOT / name
        if not path.exists():
            raise SystemExit(f"declared version target {name} does not exist")
        match = re.search(pattern, path.read_text())
        if not match:
            raise SystemExit(f"{name} no longer states a version; update TARGETS in "
                             f"tools/sync_version.py rather than deleting the check")
        found.append((name, match.group(1)))
    return found


def cli_version() -> str:
    out = subprocess.run([sys.executable, "-m", "qvault", "--version"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    match = re.search(rf"({VERSION_RE})", out)
    return match.group(1) if match else ""


def changelog_version() -> str:
    """The newest release heading in the changelog, which should be the shipped version."""
    text = (ROOT / "CHANGELOG.md").read_text()
    for line in text.splitlines():
        match = re.match(r"^## \[(\d+\.\d+\.\d+)\]", line)
        if match:
            return match.group(1)
    return ""


def check() -> int:
    want = source_version()
    problems = [f"{name} says {got}, source says {want}"
                for name, got in claimed() if got != want]

    pyproject = (ROOT / "pyproject.toml").read_text()
    if re.search(r'^version\s*=\s*["\']', pyproject, re.MULTILINE):
        problems.append("pyproject.toml pins a static version; it must stay dynamic "
                        "(version = {attr = \"qvault.__version__\"})")
    if not re.search(r'attr\s*=\s*"qvault\.__version__"', pyproject):
        problems.append("pyproject.toml no longer reads its version from qvault.__version__")

    newest_note = changelog_version()
    if newest_note != want:
        problems.append(f"CHANGELOG.md's newest heading is {newest_note or 'none'}, source says "
                        f"{want}: a release needs a note under its own heading")

    from_cli = cli_version()
    if from_cli != want:
        problems.append(f"`qvault --version` reports {from_cli or 'nothing'}, source says {want}")

    if problems:
        for line in problems:
            print(f"  - {line}")
        print("run: python3 tools/sync_version.py --write")
        return 1
    print(f"version {want}: source, README, packaging and CLI agree")
    return 0


def write() -> int:
    want = source_version()
    changed = []
    for name, pattern in TARGETS:
        path = ROOT / name
        text = path.read_text()
        match = re.search(pattern, text)
        if not match:
            raise SystemExit(f"{name} no longer matches {pattern}")
        if match.group(1) == want:
            continue
        updated = text[:match.start(1)] + want + text[match.end(1):]
        path.write_text(updated)
        changed.append(name)
    print(f"version {want}: updated {', '.join(changed) or 'nothing'}")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--check"]:
        return check()
    if argv[:1] == ["--write"]:
        return write()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

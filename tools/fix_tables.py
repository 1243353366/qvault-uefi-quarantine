#!/usr/bin/env python3
"""Rewrite every markdown table with aligned columns."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import tables  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    write = "--write" in sys.argv
    changed = 0
    targets = [ROOT / "README.md"] + sorted((ROOT / "report").glob("*.md"))
    for path in targets:
        text = path.read_text()
        fixed = tables.align(text)
        if fixed == text:
            continue
        changed += 1
        if write:
            path.write_text(fixed)
            print(f"aligned {path.relative_to(ROOT)}")
        else:
            lines = tables.misaligned(text)
            print(f"{path.relative_to(ROOT)}: {len(lines)} rows misaligned (first {lines[:3]})")
    if not write:
        print(f"{changed} file(s) need alignment; run tools/fix_tables.py --write")
        return 1 if changed else 0
    print(f"{changed} file(s) aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Pad markdown tables so columns line up in the source, not only when rendered.

A rendered table hides ragged pipes; the source is what people read in a diff. The same
alignment is applied by the generator and by the gate, so hand-editing a table cannot drift.
"""
from __future__ import annotations

import re

_MIN = 3


def _split(row: str) -> list[str]:
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def _is_separator(row: str) -> bool:
    return bool(re.fullmatch(r"\|[\s:\-|]+\|?", row.strip())) and "-" in row


def _render(rows: list[str]) -> list[str]:
    parsed = [_split(r) for r in rows]
    ncols = max(len(p) for p in parsed)
    parsed = [p + [""] * (ncols - len(p)) for p in parsed]

    sep_at = 1 if len(parsed) > 1 and _is_separator(rows[1]) else None
    body = [p for i, p in enumerate(parsed) if i != sep_at]
    widths = [_MIN] * ncols
    for row in body:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    out = []
    for index, row in enumerate(parsed):
        if index == sep_at:
            cells = []
            for i, cell in enumerate(row):
                left, right = cell.startswith(":"), cell.endswith(":")
                width = max(_MIN, widths[i])
                filler = "-" * max(1, width - (1 if left else 0) - (1 if right else 0))
                mark = (":" if left else "") + filler + (":" if right else "")
                cells.append(mark.ljust(width))
            out.append("| " + " | ".join(cells) + " |")
        else:
            out.append("| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(row)) + " |")
    return out


def align(text: str) -> str:
    """Normalise every top-level table in a markdown document."""
    out, block, fenced = [], [], False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            if block:
                out.extend(_render(block))
                block = []
            out.append(line)
            continue
        if not fenced and line.strip().startswith("|"):
            block.append(line)
            continue
        if block:
            out.extend(_render(block))
            block = []
        out.append(line)
    if block:
        out.extend(_render(block))
    return "\n".join(out)


def misaligned(text: str) -> list[int]:
    """Line numbers whose table is not in aligned form."""
    if align(text) == text:
        return []
    want = align(text).split("\n")
    got = text.split("\n")
    return [i + 1 for i, (a, b) in enumerate(zip(got, want)) if a != b][:5]

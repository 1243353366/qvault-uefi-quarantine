#!/usr/bin/env python3
"""Render report/TOOLING_RISK.md: every component that consumes untrusted input, and its gap.

Publishing a tool that parses hostile firmware adds a second attack surface to the reader's
problem. This register exists so that surface is inspectable before someone runs it, and so that a
new parser cannot be added without saying what it does not handle.

The register is deliberately pessimistic. "none observed" is a real value: where no guard was found
by reading the module, the entry says so rather than describing the intent. A hardened row keeps the
residual gap written down, because closing one attack path is not closing the class.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault import findings as F  # noqa: E402

OUT = ROOT / "report" / "TOOLING_RISK.md"

#: module -> what it consumes, the guard that was actually found by reading it, and the gap that
#: remains. `guard` is "none observed" when reading the module found no bound on the input.
REGISTER = {
    "fingerprints.py": dict(
        consumes="firmware bytes and indicator text",
        guard="text-derived grade capped at INFERRED (`MAX_TEXT_GRADE`)",
        gap="Matching is linear per indicator; an indicator set large enough to be quadratic on a "
            "hostile image is not bounded or measured."),
    "fwdiff.py": dict(
        consumes="two firmware images, arbitrary bytes",
        guard="explicit caps: MAX_FILES 4096, MAX_SECTIONS 96, MAX_PE_CANDIDATES 4",
        gap="Caps bound the count of structures, not the cost of comparing two near-identical large "
            "images inside those caps."),
    "ingest.py": dict(
        consumes="evidence blobs from an operator or an acquisition",
        guard="none observed: hashing and metadata capture; bounds come from the caller",
        gap="No independent size ceiling here, so a caller that streams an unbounded blob is trusted "
            "not to. That is an assumption, not a check."),
    "store.py": dict(
        consumes="on-disk store files, writable by anyone who reaches the volume",
        guard="`O_NOFOLLOW` + `S_ISREG` + `O_NONBLOCK` on every read, so a symlink, FIFO or device in "
              "the namespace is refused rather than followed or hung on; an object made "
              "group/world-writable after seal is refused; ids cannot traverse; the seal fsyncs the "
              "directory so a crash cannot lose the link while keeping the bytes",
        gap="The reader refuses a link and a widened mode, not a regular 0400 file an attacker wrote "
            "as a substitute. Content integrity is the envelope hash plus the audit chain; this open "
            "path does not establish it."),
    "audit.py": dict(
        consumes="audit log entries, attacker-writable between runs",
        guard="hash chain with prev_hash and seq continuity; signed Ed25519 checkpoint catches head "
              "truncation; a persisted high-water mark refuses to append to a log shorter than the "
              "last recorded count, which closes truncate-then-keep-appending",
        gap="Both controls sit on the same volume. Rewriting the mark and the log together, or "
            "holding the signing key, defeats them; closing that needs an off-box anchor (RFC 3161, "
            "a transparency log, paper custody), which is deployment and not code."),
    "provenance.py": dict(
        consumes="manifests and vendored-source trees",
        guard="`hmac.compare_digest` for secret-derived comparisons",
        gap="A modified vendored tree is caught only if its pinned hash is checked, and the pin is "
            "data in the same repository it is meant to protect."),
    "retrieve.py": dict(
        consumes="object identifiers from a caller",
        guard="`hmac.compare_digest` on identifier comparison",
        gap="Comparison is constant-time; the surrounding lookup is not, so the guarantee is about "
            "one comparison, not about the operation."),
    "keys.py": dict(
        consumes="key material and identifiers",
        guard="none observed at this layer beyond storage; comparisons are delegated",
        gap="Key lifetime and zeroisation are not enforced by the language. Python strings are "
            "immutable, so a key in memory is presumed present until the process exits."),
    "crypto.py": dict(
        consumes="sealed ciphertext, which an attacker may control",
        guard="AES-256-GCM: authentication is checked before plaintext is used",
        gap="No adversarial test of chunk framing or truncation; the framing assumptions are covered "
            "by unit tests written from the same model as the implementation."),
    "triage.py": dict(
        consumes="bytes from the vendored zbtriage engine",
        guard="vendored at a pinned revision; high-frequency indicator counting fixed after an "
              "undercount defect",
        gap="Third-party code is trusted at its pin. Its upstream changes are audited by hand, and "
            "that audit is not automated."),
    "wild.py": dict(
        consumes="the in-the-wild dataset (pinned snapshot)",
        guard="pinned snapshot; entries are metadata, not samples",
        gap="Parsed as trusted because it is vendored. If the snapshot is regenerated, nothing "
            "re-validates its schema."),
    "netobs.py": dict(
        consumes="LAN telemetry: device records, flow metadata, discovery output",
        guard="BSSID treated as context, never as a key or identity",
        gap="Records are supplied by an agent on a network the adversary may control, so identity "
            "claims are corroborated at best."),
}

#: Gaps that no entry above closes, stated once. Each is graded.
GLOBAL = (
    ("No component has been fuzzed. There is no harness in `tools/` and no corpus in the tree.",
     F.CONFIRMED),
    ("Python removes the memory-safety class (buffer overflows, use-after-free) that a C parser of "
     "the same inputs would carry. It does not remove unbounded allocation, quadratic scanning, or "
     "logic errors in length handling.", F.CORROBORATED),
    ("Handling hostile input without executing it is the design and is visible in the code; that it "
     "is robust against a determined adversary is not established, and no claim here says so.",
     F.CONFIRMED),
)


def detected() -> set[str]:
    """Modules that read bytes or parse structured input. A new one must be registered."""
    found = set()
    for path in sorted((ROOT / "qvault").glob("*.py")):
        text = path.read_text()
        if re.search(r":\s*bytes|struct\.unpack|json\.loads", text):
            found.add(path.name)
    return found


def render() -> str:
    out = ["# Tooling risk: the tool as an attack surface\n\n"]
    out.append(f"Release **{__version__}**. This project parses hostile firmware for a living, which\n"
               "makes it part of the reader's problem rather than only part of the answer. This\n"
               "register lists every component that consumes input it does not control, the guard\n"
               "found by reading that component, and the gap that remains.\n\n")
    out.append("> **Read the `none observed` rows as written.** They mean no bound was found in the\n"
               "> module, not that the module is safe. This page is a risk register, not a\n"
               "> certification, and nothing on it grades above `CORROBORATED`.\n\n")

    out.append("## Where the register stands\n\n")
    for statement, grade in GLOBAL:
        out.append(f"- {statement} *({grade})*\n")
    out.append("\n")

    out.append("## Components that parse input they do not control\n\n")
    out.append("| Module | Consumes | Guard found | Remaining gap |\n|---|---|---|---|\n")
    for module, entry in REGISTER.items():
        out.append(f"| `qvault/{module}` | {entry['consumes']} | {entry['guard']} | {entry['gap']} |\n")
    out.append("\n")
    out.append(f"{len(REGISTER)} registered components. A test fails if a module takes `bytes` or "
               "parses JSON and is missing from this table, so the register stays complete as the "
               "code grows.\n\n")

    out.append("## What a reader should do with it\n\n")
    out.append("Run this on a machine you can rebuild. Treat the evidence store as data written by "
               "an adversary, because a bootkit that knows it is being collected will try to write "
               "it. Neither of those is a paranoid reading of the code; both follow from the rows "
               "above.\n\n")

    out.append("## What this page does not claim\n\n")
    out.append("It does not claim the parsers are safe, bounded, or audited by anyone other than "
               "this project. It claims that each component consuming untrusted input is named, "
               "that its guard is described at the level it was verified, and that its gap is "
               "written down rather than left for a reader to discover during an incident.\n")
    return "".join(out)


def assert_register_complete() -> None:
    missing = sorted(detected() - set(REGISTER))
    if missing:
        raise ValueError(f"unregistered input-parsing modules: {', '.join(missing)}")


def main() -> int:
    assert_register_complete()
    OUT.write_text(tables.align(render()))
    print(f"wrote {OUT.relative_to(ROOT)} ({len(REGISTER)} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Render report/CDUP.md from the subsystem's own properties.

The page exists to be falsifiable: every row names where the behaviour is implemented and what grade
it holds. Rows that are not implemented say so instead of being omitted.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault import findings as F  # noqa: E402

OUT = ROOT / "report" / "CDUP.md"

#: stage, what the attacker gets, whether CDUP protects it, grade
EXPOSURES = [
    ("1. Before encryption", "A keylogger, screen recorder or input hook reads plaintext the "
     "application has not encrypted yet.", "**No.** CDUP never sees this data.",
     "CONFIRMED (limitation)"),
    ("2. During processing", "Malware reads application memory while a document is decrypted for "
     "use.", "**Partly.** The window is bounded and audited; memory is not zeroised.",
     "CORROBORATED (limitation)"),
    ("3. After encryption", "The attacker copies ciphertext without the key.", "**Yes.** This is the "
     "working case, tested from the attacker's side.", "CONFIRMED"),
    ("4. During transmission", "The attacker intercepts the encrypted payload.", "**Yes, if the "
     "authority is not co-located.** Depends on deployment, not on this module.", "CORROBORATED"),
]

#: property, implemented by, grade
PROPERTIES = [
    ("Application-level encryption", "`cdup.put` encrypts before anything reaches the store", "CONFIRMED"),
    ("Per-object encryption keys", "`put` draws a fresh DEK per object; nothing is shared", "CONFIRMED"),
    ("Hardware-backed key protection", "**not implemented.** The authority is a 0600 file; an HSM is "
     "deployment work", "UNKNOWN"),
    ("Explicit decryption authorization", "`KeyAuthority.issue` / `open_dek`; nothing decrypts "
     "without a capability", "CONFIRMED"),
    ("Short-lived decryption capabilities", "TTL checked against a clock; expiry is a refusal", "CONFIRMED"),
    ("Key separation", "`assert_separated` refuses a nested tree; capability MACs use an HKDF subkey, "
     "not the KEK", "CONFIRMED"),
    ("Authenticated encryption", "AES-256-GCM per chunk, AAD-bound to the object id, so ciphertext "
     "cannot be relabelled", "CONFIRMED"),
    ("Access auditing", "`cdup.seal`, `cdup.issue`, `cdup.open`, `cdup.deny` in the hash-chained log",
     "CONFIRMED"),
]

#: open tests - the questions this page cannot answer
OPEN_TESTS = [
    ("Does a stolen session cookie defeat the boundary?",
     "Not tested. There is no network API or session authentication here, so a cookie cannot reach "
     "the authority at all - the question is deferred, not answered.", "UNKNOWN"),
    ("Is plaintext recoverable from memory during `get`?",
     "Almost certainly yes. Python strings and buffers cannot be reliably zeroised; the capability "
     "bounds when decryption happens, not what an observer with memory access can see.", "HYPOTHESIS"),
    ("Does the separation survive a compromised endpoint?",
     "Only if the authority runs where the endpoint cannot read it. Same-host authority that "
     "cooperates automatically is architectural decoration.", "INFERRED"),
    ("Does this help against a keylogger?",
     "No. Stage 1 is untouched, and no amount of encryption after the fact recovers it.", "CONFIRMED (limitation)"),
]


def render() -> str:
    o = ["# CDUP: Cryptographic Data Usability Protection\n\n"]
    o.append(f"Release **{__version__}**, branch `feature/cdup`, not merged. The legal-exposure reason for\n"
             "keeping it off `main` is stated at the end of this page.\n\n")
    o.append("**Objective.** Assume an attacker acquires the payload. Minimise what they can recover from\n"
             "it.\n\n")
    o.append("The premise is not paranoia. Infostealers are sold as malware-as-a-service, so an attacker\n"
             "who cannot write malware can rent collection, and Recorded Future's 2025 data puts the yield\n"
             "at roughly 87 stolen credentials per compromised device. The interesting question is not\n"
             "whether the payload is stolen but what a stolen payload is worth.\n\n")

    o.append("## Where encryption helps, and where it cannot\n\n")
    o.append("| Stage | What the attacker gets | Does CDUP protect it | Grade |\n|---|---|---|---|\n")
    for stage, gets, protects, grade in EXPOSURES:
        o.append(f"| {stage} | {gets} | {protects} | {grade} |\n")
    o.append("\n")

    o.append("## The properties, and where each one lives\n\n")
    o.append("| Property | Implemented by | Grade |\n|---|---|---|\n")
    for prop, where, grade in PROPERTIES:
        o.append(f"| {prop} | {where} | {grade} |\n")
    o.append("\n")

    o.append("## The load-bearing control is the authority, not the cipher\n\n")
    o.append("```\nplaintext ──▶ AES-256-GCM (fresh DEK) ──▶ ciphertext ──▶ store  (no key material)\n"
             "                     │\n"
             "                     └── DEK wrapped under the KEK ──▶ held by the authority\n\n"
             "decrypt:  capability ──▶ authority checks mac, expiry, binding, replay ──▶ DEK\n```\n\n")
    o.append("A machine that holds the store cannot decrypt it. That is the whole design, and it is only\n"
             "true while the authority is somewhere the endpoint cannot read. If the authority runs on the\n"
             "same host and answers whatever asks, the separation is an envelope with extra steps, and this\n"
             "page should be read as describing an envelope.\n\n")

    o.append("## Refusals are intentionally indistinguishable\n\n")
    o.append("Expired, forged, replayed and wrong-object capabilities all raise the same string,\n"
             "`decryption not available`. The reason is written to the audit log, which an authorised\n"
             "observer reads, rather than to the caller, who may be probing. A test asserts that all four\n"
             "messages are byte-identical, because a helpful error is an oracle.\n\n")

    o.append("## What is tested, from the attacker's side\n\n")
    o.append("Thirteen tests in `qvault/tests/test_cdup.py`: roundtrip; the store contains no key material;\n"
             "expired refused; capability for another object refused; forged lifetime refused; replay refused;\n"
             "repeatable capability when explicitly asked for; ciphertext swapped between objects refused;\n"
             "capability from a rival authority refused; identical refusals; nested authority tree refused;\n"
             "refusals audited; default lifetime bounded.\n\n")

    o.append("## Open tests this page cannot pass\n\n")
    o.append("| Question | State | Grade |\n|---|---|---|\n")
    for q, state, grade in OPEN_TESTS:
        o.append(f"| {q} | {state} | {grade} |\n")
    o.append("\n")

    o.append("## Why this is on a branch, and what robots.txt can and cannot do\n\n")
    o.append("This subsystem invites a different legal reading from the rest of the repository: it is key\n"
             "management for data whose owner is not necessarily the person running it. Nothing here\n"
             "collects, decrypts or transmits data belonging to anyone else, and no network interface is\n"
             "implemented - but the capability model is exactly what a lawful-access feature would need, so\n"
             "it stays off `main` until that is thought through rather than assumed.\n\n")
    o.append("It is in the page registry, so it joins the sitemap the moment the branch is merged and the\n"
             "site rebuilds. **`robots.txt` cannot index a branch.** Crawlers read the built site; a page\n"
             "that is not published has nothing to crawl, and adding a path to `robots.txt` on `main`\n"
             "would point at a 404. Merge is the publication step, not a robots entry.\n")
    return "".join(o)


def main() -> int:
    def graded(value: str) -> bool:
        """A limitation is graded like any claim, with a parenthetical saying what kind it is."""
        base = value.split(" (")[0]
        return base in F.GRADES

    for row in EXPOSURES:
        assert graded(row[3]), row[3]
    for row in PROPERTIES:
        assert graded(row[2]), row[2]
    for row in OPEN_TESTS:
        assert graded(row[2]), row[2]
    OUT.write_text(tables.align(render()))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

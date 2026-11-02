#!/usr/bin/env python3
"""Render report/THREAT_INTEL.md from the module's own ceilings, channels and doctrine."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault.evidence_brief import (ALLOWED_METHODS, IDENTITY_PATTERNS,  # noqa: E402
                                   LAWFUL_ROUTES)
from qvault.threatintel import CLAIM_CEILINGS, FORBIDDEN_SOURCES, REPORT_CHANNELS  # noqa: E402

OUT = ROOT / "report" / "THREAT_INTEL.md"

DIMENSIONS = [
    ("Infrastructure", "Domains, hosting, IPs, C2", "Passive observation, provider disclosure"),
    ("Distribution", "Telegram channels, Tor services, delivery", "Published reporting, platform abuse records"),
    ("Financial", "Wallets, transactions, payment routes", "Public ledger, exchange disclosure with lawful basis"),
    ("Technical", "Sample hashes, certificates, reused artefacts", "Sample analysis, certificate transparency"),
    ("Evidence correlation", "Provenance, timestamps, independence, alternatives", "This module"),
]

DOCTRINE = [
    ("No active collection",
     "`add` refuses probe, forced-rotation, credential-use, purchase, wallet-interaction and intrusion "
     "sources; the module contains no network code at all",
     "test_collection_sources_are_refused"),
    ("No default for unknowns",
     "an unrecognised source, claim or entity kind raises rather than being trusted",
     "test_an_unknown_source_has_no_default"),
    ("No independence laundering",
     "the grade comes from provenance roots, so four rows derived from one report count once",
     "test_four_rows_from_one_root_are_still_one_observation"),
    ("No attribution verdict",
     "per-claim ceilings cap operator, wallet and proxy attribution at HYPOTHESIS, and the output has "
     "no identity field",
     "test_operator_attribution_never_exceeds_hypothesis"),
    ("No retaliation",
     "`disruption_plan` emits report/notify/preserve/submit against named external channels, and "
     "refuses any other verb",
     "test_disruption_is_reporting_only"),
]

REFUSALS = [
    ("Hash mismatch", "the bytes on disk do not hash to the recorded digest"),
    ("Timestamp in the future", "a clock is wrong, or the record was written ahead of the event"),
    ("Naive timestamp", "a local time with no timezone is not evidence"),
    ("Undocumented method", "acquisition method outside the recorded set"),
    ("Unattributed artefact", "no acquiring party recorded"),
    ("Artefact missing", "the original is not where the case says it is"),
    ("Writable original", "immutability is a mode, not a promise in a header"),
    ("Phrasing that names a person", "the hypothesis equates an artefact with a person"),
    ("Self-declared CORROBORATED", "a hypothesis cannot grade itself; cite observations"),
    ("No competing explanation", "an attribution claim without an alternative is an accusation"),
]

RESEARCH = """## The research direction this page takes, and why

Two directions were on the table: **A**, the financial trail, and **B**, the operational graph.

**B first.** The financial trail dead-ends exactly where the doctrine requires it to: exchange records
need lawful process, so a passive-only pipeline produces wallet clusters with no subject attached and
stops. The operational graph is buildable from passive observation, and every disruption avenue in the
table above is technical. Finance is the second pass, and its job is to tell you which of the nodes you
already mapped are worth reporting on.

The one exception worth carving out early is the ledger-pointer case: when infrastructure is fetched
from a public chain, the financial and technical questions collapse into the same artefact, and a
domain blocklist stops being a fix.
"""


def render() -> str:
    o = ["# Threat intelligence and adversary disruption\n\n"]
    o.append(f"Release **{__version__}**, branch `feature/threatintel`, not merged.\n\n")
    o.append("Three questions, kept apart on purpose: **what software is operating** (the malware "
             "evidence graph), **what infrastructure it depends on**, and **how the operation finances "
             "itself**. They are separated because a wallet in a sample and a wallet in an advertisement "
             "support \"related artefacts\", not \"this person runs that device\", and a module that "
             "blurs the two produces confident nonsense.\n\n")
    o.append("This module is analysis and packaging. It has no blockchain client, no exchange data and "
             "no live feeds; it reasons over evidence somebody else lawfully obtained.\n\n")

    o.append("## The five dimensions\n\n")
    o.append("| Dimension | Contents | Usual passive source |\n|---|---|---|\n")
    for name, contents, source in DIMENSIONS:
        o.append(f"| {name} | {contents} | {source} |\n")
    o.append("\n")

    o.append("## The doctrine is enforced, not documented\n\n")
    o.append("| Rule | Where it is enforced | Test |\n|---|---|---|\n")
    for rule, where, test in DOCTRINE:
        o.append(f"| {rule} | {where} | `{test}` |\n")
    o.append("\n")
    o.append("Sources refused outright: " + ", ".join(f"`{s}`" for s in sorted(FORBIDDEN_SOURCES)) +
             ". In the US, lawful reporting runs through the FBI IC3 and the relevant CERT; nothing in "
             "this module contacts anyone.\n\n")

    o.append("## Claim ceilings\n\n")
    o.append("| Claim | Highest grade passive evidence can reach |\n|---|---|\n")
    for claim, ceiling in CLAIM_CEILINGS.items():
        o.append(f"| `{claim}` | {ceiling} |\n")
    o.append("\n")
    o.append("`CONFIRMED` is absent from every attribution row by construction. It is not that attribution "
             "is impossible; it is that this module cannot do it, and a ceiling is a cheaper safeguard "
             "than an analyst's discipline at 2am.\n\n")

    o.append("## Lawful disruption avenues\n\n")
    o.append("| Artefact | Action | Channel |\n|---|---|---|\n")
    for kind, (channel, action) in REPORT_CHANNELS.items():
        o.append(f"| `{kind}` | {action} | {channel} |\n")
    o.append("\n")

    o.append("## Ledger pointers: where a takedown is not a fix\n\n")
    o.append("If a sample resolves its infrastructure through a public ledger, blocking the domains removes "
             "the current C2 and leaves the rediscovery path intact. `deleted_domains_are_not_enough` "
             "reports that dependency as `blockchain_dependent: true` with grade `INFERRED`, and returns "
             "`UNKNOWN` with an explicit \"absence of evidence\" note when no pointer is observed. The "
             "second case matters: no pointer is not a clean sample.\n\n")

    o.append("## What a package contains, and what it refuses to conclude\n\n")
    o.append("Hashed artefacts with provenance, the graded graph, hypotheses, one competing explanation "
             "per hypothesis, and a list of what the package does not establish: who controls a wallet, "
             "domain or account; that related artefacts share an operator; that a device belongs to any "
             "identified person. A package that omits the competing explanation is refused.\n\n")

    o.append("## Two bugs this module found in itself\n\n")
    o.append("A derived observation once hashed to its parent's id, so a two-step derivation made the "
             "provenance walk follow itself and the test **hung instead of failing**. Identity now covers "
             "every field, and the walk refuses cycles. Both are tested.\n\n")
    o.append("The tests were written from the analyst's side of the desk rather than the attacker's: try to "
             "launder one source into four, promote a wallet to an owner, and turn a rotation into an "
             "attribution. Twenty-four tests; the ceilings hold.\n\n")

    o.append("## Evidence before attribution: the filing brief\n\n")
    o.append("`qvault/evidence_brief.py` turns a case into a document that can be handed to an "
             "investigator, and refuses to produce one when the custody chain has a defect. Refusal is the "
             "design: a brief annotated \"warning: hash mismatch\" invites a reader to trust a package the "
             "analyst already knew was broken.\n\n")
    o.append("| Defect | Why it stops the brief |\n|---|---|\n")
    for defect, why in REFUSALS:
        o.append(f"| {defect} | {why} |\n")
    o.append("\n")
    o.append("Acquisition methods accepted: " +
             ", ".join(f"`{m}`" for m in sorted(ALLOWED_METHODS)) + ".\n\n")
    o.append("There is no `owner`, `identity` or `suspect` field anywhere in the structure, so the shortcut "
             "of writing a name beside an artefact is not available. The hypothesis is carried with a "
             "grade and next to a required competing explanation. The identity lint is "
             f"{len(IDENTITY_PATTERNS)} patterns for attributive phrasing; it catches \"is operated by "
             "<Name>\" and cannot catch implication by layout or by a name left in a filename. The "
             "structural limits do the work; the lint is a tripwire.\n\n")
    o.append("Every brief carries a manifest hash over its artefacts, hypothesis and grade, and "
             "`python -m qvault.evidence_brief verify FILE.json` recomputes it: a mismatch means the "
             "document was edited after generation.\n\n")

    o.append("### Where it goes next\n\n")
    o.append("| Jurisdiction | Channel | Action |\n|---|---|---|\n")
    for jurisdiction, channel, action in LAWFUL_ROUTES:
        o.append(f"| {jurisdiction} | {channel} | {action} |\n")
    o.append("\nThe brief states that it contacted nobody. Filing is the analyst's act, not the tool's.\n\n")

    o.append("### Two checks that were quietly broken\n\n")
    o.append("`os.access(path, os.W_OK)` returns True for a 0400 file when the process runs as root, so the "
             "obvious immutability check passed on every artefact in a root container, which is where this "
             "runs. The check now reads the mode bits.\n\n")
    o.append("Git does not preserve anything but the executable bit, so an example artefact checked out of a "
             "repository arrives writable and is correctly refused. The demo case is therefore local only, "
             "listed in `.gitignore`, rather than committed as a broken example.\n\n")

    o.append(RESEARCH)
    o.append("\n## Why this is off `main`\n\n")
    o.append("Attribution and financial analysis carry a different legal reading from the containment "
             "engine, and a module that names wallets and channels is a different publication than one "
             "that quarantines firmware. It stays on a branch until that reading is settled deliberately. "
             "It is in the page registry, so merging publishes it and the sitemap lists it; `robots.txt` "
             "cannot index an unmerged branch, because there is nothing built to crawl.\n")
    return "".join(o)


def main() -> int:
    OUT.write_text(tables.align(render()))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

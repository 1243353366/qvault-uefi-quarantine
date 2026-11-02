"""
qvault.evidence_brief
=====================

Turn a case into something that can be handed to an investigator: hashes, times, acquisition methods,
provenance, immutable originals, graded hypotheses, and a plain statement of what the evidence does
not establish.

The ordering matters and is not negotiable here: **evidence before attribution.** No field in this
module associates a wallet, IP address, domain or Telegram account with a person. There is no `owner`,
no `identity`, no `suspect` field to fill in, so the shortcut is not available to take at 2am. The
hypothesis is carried as a hypothesis with a grade, next to a competing explanation that is required.

Refusal over warning
--------------------
Every custody defect stops the brief instead of annotating it:

* an artefact whose bytes do not hash to the recorded digest,
* a missing acquisition method, acquiring party, or timestamp,
* a timestamp in the future, or one without a timezone,
* an original that is writable (immutability is a property of the file, not a promise in a header),
* a hypothesis that equates infrastructure with a person.

A brief that says "warning: hash mismatch" is worse than no brief: it invites the reader to trust a
package the analyst already knew was broken.

What a regex cannot do
----------------------
The identity lint catches attributive phrasing ("is operated by <Name>"). It cannot catch implication
by layout, by omission, or by a name dropped in a filename. The structural limits do the heavy
lifting; the lint is a tripwire, and this paragraph is the honest description of its reach.

Lawful route
------------
The output is for filing: FBI IC3 for US cybercrime, the relevant national CERT, and the provider
abuse desks named per artefact. This module contacts nobody, and the brief says so.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from qvault.threatintel import (GRADES, Assessor, DoctrineViolation, IntelligenceError,
                               Observation, disruption_plan)

#: How an artefact came to be in the case. Anything else is refused: an unexplained provenance chain
#: is not a custody chain.
ALLOWED_METHODS = frozenset({
    "passive_capture",      # traffic or artefacts already present on a host you control
    "disk_image",           # write-blocked acquisition
    "memory_image",
    "provider_disclosure",  # hosting, registrar, exchange, with a lawful basis
    "public_record",        # certificate transparency, public ledger read
    "sample_analysis",      # analyst worked on a copy
    "log_export",
})

#: Tripwires for equating an artefact with a person. Deliberately narrow: false positives cost a
#: rewrite, false negatives cost credibility.
IDENTITY_PATTERNS = (
    re.compile(r"\b(is|was)\s+(operated|run|owned|controlled|registered)\s+by\s+[A-Z][a-z]+", re.I),
    re.compile(r"\bbelongs?\s+to\s+[A-Z][a-z]+\s+[A-Z][a-z]+", re.I),
    re.compile(r"\b(attacker|operator)\s+is\s+(named\s+)?[A-Z][a-z]+\s+[A-Z][a-z]+", re.I),
    re.compile(r"\b(identified|confirmed)\s+as\s+[A-Z][a-z]+\s+[A-Z][a-z]+", re.I),
)

CLOCK_SKEW = timedelta(minutes=5)


def _writable(path: str) -> bool:
    """Whether the artefact's mode grants write access to anyone.

    Deliberately the mode bits rather than `os.access`: as root, `os.access(path, W_OK)` returns True
    for a 0400 file, so the obvious check silently passes on every artefact in a root container - which
    is exactly where this runs. The mode is also what a lab attests to when it hands over an original.
    """
    return bool(os.stat(path).st_mode & 0o222)

LAWFUL_ROUTES = [
    ("US cybercrime", "FBI Internet Crime Complaint Center (IC3)", "file the brief and custody manifest"),
    ("National CERT", "the CERT of the victim's jurisdiction", "notify and attach the manifest hash"),
    ("Hosting or registrar", "the provider's abuse desk, per artefact", "report the artefact"),
    ("Exchange", "compliance team, for a wallet artefact", "submit the intelligence, not a demand"),
]


@dataclass(frozen=True)
class Artifact:
    name: str
    path: str
    sha256: str
    acquired_at: str
    acquired_by: str
    method: str
    source: str


def _parse_time(value: str, now: datetime) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise DoctrineViolation("acquisition timestamp missing")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise DoctrineViolation(f"acquisition timestamp not ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise DoctrineViolation("acquisition timestamp has no timezone: a local time is not evidence")
    if parsed > now + CLOCK_SKEW:
        raise DoctrineViolation(f"acquisition timestamp is in the future: {value!r}")
    return parsed


def check_artifact(art: Artifact, *, now: datetime | None = None) -> dict:
    """Verify one artefact. Returns its custody record, or raises on the first defect."""
    now = now or datetime.now(timezone.utc)
    when = _parse_time(art.acquired_at, now)
    if art.method not in ALLOWED_METHODS:
        raise DoctrineViolation(f"acquisition method {art.method!r} is not a documented method")
    if not art.acquired_by.strip():
        raise DoctrineViolation("acquiring party missing: an unattributed artefact is not evidence")
    if not art.source.strip():
        raise DoctrineViolation(f"source provenance missing for {art.name!r}")
    if not os.path.exists(art.path):
        raise DoctrineViolation(f"artefact not found on disk: {art.name!r}")
    if _writable(art.path):
        raise DoctrineViolation(f"original is writable: {art.name!r} is not preserved")
    digest = hashlib.sha256(open(art.path, "rb").read()).hexdigest()
    if digest != art.sha256.lower():
        raise DoctrineViolation(f"hash mismatch for {art.name!r}: recorded {art.sha256[:12]}, "
                                f"on disk {digest[:12]}")
    return {"name": art.name, "sha256": digest, "bytes": os.path.getsize(art.path),
            "acquired_at": when.isoformat(), "acquired_by": art.acquired_by,
            "method": art.method, "source": art.source,
            "immutable": not _writable(art.path)}


def lint_hypothesis(text: str) -> str:
    """Refuse phrasing that asserts a person behind an artefact."""
    if not text.strip():
        raise DoctrineViolation("hypothesis is empty")
    for pattern in IDENTITY_PATTERNS:
        found = pattern.search(text)
        if found:
            raise DoctrineViolation(f"hypothesis equates an artefact with a person: {found.group(0)!r}")
    return text.strip()


def build_brief(case: dict, *, now: datetime | None = None) -> dict:
    """Assemble the filing package. Refuses anything with a custody or doctrine defect."""
    now = now or datetime.now(timezone.utc)
    for field in ("case", "analyst", "artifacts", "observations", "hypothesis", "alternatives"):
        if field not in case:
            raise IntelligenceError(f"case is missing {field!r}")

    custody = [check_artifact(Artifact(**a), now=now) for a in case["artifacts"]]
    if not custody:
        raise IntelligenceError("a case with no artefacts is a rumour")

    assessor = Assessor()
    for raw in case["observations"]:
        assessor.add(Observation(**{k: tuple(v) if isinstance(v, list) else v
                                    for k, v in raw.items()}))

    hypothesis = lint_hypothesis(str(case["hypothesis"]))
    grade = case.get("hypothesis_grade", "HYPOTHESIS")
    if grade not in GRADES:
        raise IntelligenceError(f"unknown hypothesis grade {grade!r}")
    if grade in ("CONFIRMED", "CORROBORATED"):
        raise DoctrineViolation("a hypothesis is not CORROBORATED by declaring it so; cite the "
                                "observations and let the grade be computed")

    alternatives = case["alternatives"]
    attribution_claims = [h["claim"] for h in assessor.attribution()]
    for claim in attribution_claims:
        if claim not in alternatives:
            raise DoctrineViolation(f"no competing explanation for {claim!r}")

    timeline = sorted(({"at": c["acquired_at"], "event": f"acquired {c['name']}"} for c in custody),
                      key=lambda e: e["at"])

    manifest = {"case": case["case"], "artifacts": custody,
                "hypothesis": hypothesis, "hypothesis_grade": grade}
    manifest_hash = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    return {
        "case": case["case"],
        "analyst": case["analyst"],
        "generated_at": now.isoformat(),
        "artifacts": custody,
        "timeline": timeline,
        "graph": assessor.graph(),
        "hypotheses": assessor.attribution(),
        "hypothesis": hypothesis,
        "hypothesis_grade": grade,
        "alternatives": dict(alternatives),
        "disruption": disruption_plan(sorted({e for o in case["observations"]
                                              for e in o.get("entities", [])})),
        "lawful_routes": [{"jurisdiction": j, "channel": c, "action": a} for j, c, a in LAWFUL_ROUTES],
        "does_not_establish": [
            "who controls a wallet, IP address, domain, or Telegram account",
            "that related artefacts share an operator",
            "that any device belongs to an identified person",
        ],
        "contacts_made": "none: this module produces a document, and it contacts nobody",
        "manifest_sha256": manifest_hash,
    }


def verify_brief(brief: dict) -> bool:
    """Recompute the manifest hash. A brief whose manifest does not match has been edited."""
    manifest = {"case": brief["case"], "artifacts": brief["artifacts"],
                "hypothesis": brief["hypothesis"], "hypothesis_grade": brief["hypothesis_grade"]}
    digest = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return digest == brief.get("manifest_sha256")


def render_markdown(brief: dict) -> str:
    o = [f"# Evidence brief: {brief['case']}\n\n",
         f"Prepared by **{brief['analyst']}**, generated {brief['generated_at']}.\n\n",
         "This document summarises evidence and a hypothesis. It does not identify any person as the\n"
         "operator of any wallet, address, domain or account, and no such identification should be\n"
         "inferred from it.\n\n"]

    o.append("## Artefacts and custody\n\n")
    o.append("| Artefact | SHA-256 | Bytes | Acquired (UTC) | By | Method | Source | Immutable |\n")
    o.append("|---|---|---|---|---|---|---|---|\n")
    for c in brief["artifacts"]:
        o.append(f"| `{c['name']}` | `{c['sha256']}` | {c['bytes']} | {c['acquired_at']} | "
                 f"{c['acquired_by']} | {c['method']} | {c['source']} | "
                 f"{'yes' if c['immutable'] else 'NO'} |\n")
    o.append(f"\nManifest SHA-256: `{brief['manifest_sha256']}`. Verify with "
             "`python -m qvault.evidence_brief verify FILE.json`; a mismatch means the brief was edited.\n\n")

    o.append("## Timeline\n\n")
    for event in brief["timeline"]:
        o.append(f"- {event['at']}: {event['event']}\n")
    o.append("\n")

    o.append("## Hypothesis, carried as a hypothesis\n\n")
    o.append(f"> {brief['hypothesis']}\n\n")
    o.append(f"Grade: **{brief['hypothesis_grade']}**. Competing explanations are recorded below; the\n"
             "hypothesis is not asserted as fact.\n\n")

    o.append("## Computed attribution grades\n\n")
    if brief["hypotheses"]:
        o.append("| Claim | Grade | Independent roots | Ceiling |\n|---|---|---|---|\n")
        for h in brief["hypotheses"]:
            o.append(f"| {h['claim']} | {h['grade']} | {h['independent_roots']} | {h['ceiling']} |\n")
    else:
        o.append("No attribution claim is present in this case.\n")
    o.append("\n")

    o.append("## Competing explanations\n\n")
    for claim, text in brief["alternatives"].items():
        o.append(f"- **{claim}**: {text}\n")
    o.append("\n")

    o.append("## What this evidence does not establish\n\n")
    for line in brief["does_not_establish"]:
        o.append(f"- {line}\n")
    o.append("\n")

    o.append("## Lawful routes for this package\n\n")
    o.append("| Jurisdiction | Channel | Action |\n|---|---|---|\n")
    for route in brief["lawful_routes"]:
        o.append(f"| {route['jurisdiction']} | {route['channel']} | {route['action']} |\n")
    o.append(f"\n{brief['contacts_made']}.\n")
    return "".join(o)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qvault.evidence_brief", description=__doc__.split("\n")[1])
    sub = parser.add_subparsers(dest="cmd", required=True)
    make = sub.add_parser("build", help="build a brief from a case file")
    make.add_argument("case", help="case JSON")
    make.add_argument("--out", default="-", help="markdown output path, or - for stdout")
    make.add_argument("--json", default=None, help="also write the machine-readable brief here")
    check = sub.add_parser("verify", help="recompute the manifest hash of a brief")
    check.add_argument("brief", help="brief JSON produced by build --json")
    args = parser.parse_args(argv)

    if args.cmd == "verify":
        brief = json.load(open(args.brief))
        ok = verify_brief(brief)
        print("manifest OK" if ok else "MANIFEST MISMATCH: the brief was edited after generation")
        return 0 if ok else 1

    try:
        case = json.load(open(args.case))
        brief = build_brief(case)
    except (DoctrineViolation, IntelligenceError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    markdown = render_markdown(brief)
    if args.out == "-":
        sys.stdout.write(markdown)
    else:
        with open(args.out, "w") as fh:
            fh.write(markdown)
        print(f"wrote {args.out}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(brief, fh, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

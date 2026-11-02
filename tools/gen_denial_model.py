#!/usr/bin/env python3
"""Render report/DENIAL_MODEL.md from qvault.denial."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qvault import denial as D  # noqa: E402
from qvault import findings as F  # noqa: E402

import tables  # noqa: E402

OUT = ROOT / "report" / "DENIAL_MODEL.md"


def render() -> str:
    out = ["# Denial model: three postures and the conditions that end them\n\n"]
    out.append(
        "Three ways to deny an attacker, kept apart because they fail differently. Each one is a\n"
        "statement about an adversary's *inability*, and inability is the hardest claim to establish\n"
        "from inside the system being attacked. So each posture carries its non-claims and the\n"
        "condition under which the denial ends.\n\n")
    out.append(
        "> These are not detections and not verdicts. A posture is a control. This page grades the\n"
        "> claim that the control is holding, and records what it cannot do. The verdict engine\n"
        "> remains single-owner; nothing here decides whether a host is compromised.\n\n")

    out.append("## The three postures\n\n")
    out.append("| Posture | Denies | Load-bearing control | Ceiling | Availability cost |\n")
    out.append("|---|---|---|---|---|\n")
    for posture in D.POSTURES:
        grade = D.assess(posture.name, plane="hardware", corroborating_evidence=3,
                         enforced_by_target=False)["grade"]
        out.append(f"| `{posture.name}` | {posture.denies} | {posture.load_bearing} | "
                   f"{grade} | {posture.availability_cost} |\n")
    out.append("\n")

    for posture in D.POSTURES:
        out.append(f"## `{posture.name}`\n\n")
        out.append(f"**Denies.** {posture.denies}.\n\n")
        out.append(f"**Load-bearing.** {posture.load_bearing}.\n\n")
        out.append("**Stops:**\n\n")
        for item in posture.stops:
            out.append(f"- {item}\n")
        out.append("\n**Does not stop:**\n\n")
        for item in posture.does_not_stop:
            out.append(f"- {item}\n")
        out.append(f"\n**Denial ends when:** {posture.restored_when}.\n\n")
        out.append(f"**Cost of being wrong:** {posture.availability_cost}.\n\n")

    out.append("## What each enforcement plane can support\n\n")
    out.append("A control is only as strong as the plane it sits on. A plane inside the thing being\n"
               "attacked is a preference, not an enforcement.\n\n")
    out.append("| Plane | Ceiling | Why |\n|---|---|---|\n")
    why = {
        "hardware": "the host cannot rewrite it without physical access",
        "external_key": "the key is outside the host's trust domain, so a host compromise is not a key compromise",
        "out_of_band": "a different machine or a port the host cannot reprogram",
        "supply_chain": "a signed revocation that has actually been applied",
        "in_band": "policy running on the host it constrains, so compromising the host compromises the control",
        "absent": "asserted with nothing behind it",
    }
    for plane in D.PLANES:
        out.append(f"| `{plane}` | {D.PLANE_CEILING[plane]} | {why[plane]} |\n")
    out.append("\n")
    out.append("No plane reaches CONFIRMED, and the gate refuses one that tries. CONFIRMED is for\n"
               "things present in the evidence; \"the attacker could not\" is inferred from the\n"
               "absence of a success, and absence of evidence is what this project refuses to\n"
               "promote. The strongest a denial claim gets is CORROBORATED.\n\n")

    out.append("## Three postures, one mistake\n\n")
    out.append("| Combination | What it means |\n|---|---|\n")
    for pair, meaning in D.COMPOSITION:
        out.append(f"| {pair} | {meaning} |\n")
    out.append("\n")
    out.append("The independence test is the plane, not the label. Three denials enforced by one\n"
               "authority are one denial: a key held by the same service that signs the allow list\n"
               "is a single compromise away from both.\n\n")

    out.append("## Worked against the three families\n\n")
    out.append("| Family | Posture that applies | Plane | Grade | What it does not give you |\n")
    out.append("|---|---|---|---|---|\n")
    out.append("| LoJax | `deny_capability` (SPI write protection), then `deny_execution` | hardware | "
               "CORROBORATED | an implant already in flash keeps booting: protection stops the write, "
               "not the resident |\n")
    out.append("| MoonBounce | `deny_capability` on the flash descriptor, `deny_access` for the collected "
               "image | hardware, external_key | CORROBORATED | the dump is only as good as the "
               "programmer that read it, and an encrypted archive is not a trusted one |\n")
    out.append("| BlackLotus | `deny_execution` by revocation | supply_chain | INFERRED until the "
               "revocation is actually applied, CORROBORATED after | a signed-but-later-revoked "
               "bootloader still runs on every machine that never applied the update |\n")
    out.append("\n")
    out.append("BlackLotus is where the supply-chain plane is easiest to mistake for a hardware one. The\n"
               "control is real, but it lives in an update pipeline: the denial holds on the machines\n"
               "that shipped the revocation and nowhere else. That is why the grade depends on\n"
               "application, not on the advisory existing.\n\n")

    out.append("## What all three share\n\n")
    out.append("Every posture above assumes something below it is intact. Deny execution assumes the\n"
               "verifier's root is trusted; deny capability assumes the enumeration of what the code\n"
               "needs is complete; deny access assumes the key was never where the payload was. A\n"
               "bootkit voids the in-band versions of all three at once, which is the same limit the\n"
               "architectural limitations page records as A1 and A5.\n")
    return "".join(out)


def main() -> int:
    OUT.write_text(tables.align(render()))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

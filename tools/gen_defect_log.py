#!/usr/bin/env python3
"""Render report/DEFECT_LOG.md: the project's own failures, graded like any other claim.

A project whose thesis is "do not promote absence, do not overstate" has no honest way to show a
green badge without showing what red taught it. So the defects are data here, each with how it was
found, what fixed it, what it bought, and what it cost - and the causal claims about the benefit
are graded INFERRED, because "this fix prevents that class" is a prediction, not an observation.

Generated so the counts stay true: `version` and the gate count are read at build time.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import gates  # noqa: E402
import tables  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault import findings as F  # noqa: E402

OUT = ROOT / "report" / "DEFECT_LOG.md"

#: phase = where the defect lived. This is the finding: five of six sit on a boundary between
#: phases, not inside the code, and the local gates run entirely within one phase.
EVENTS = (
    {
        "key": "D1",
        "title": "CI was declared before it ever ran",
        "phase": "publish",
        "what": "The badge, the workflow file and the claim that CI runs the suite were all in the "
                "README while the workflow had never executed: the OAuth token lacked the `workflow` "
                "scope, so the push carrying `ci.yml` was rejected. The badge was removed rather "
                "than left implying a run that did not exist.",
        "found": "A push that failed to carry the file, checked instead of assumed.",
        "fix": "The scope was authorized, the workflow landed, and the first real run went red on a "
               "missing dependency (`markdown`, absent from the lock file but present in every "
               "developer venv). `requirements-dev.txt` now pins it.",
        "artifacts": ("requirements-dev.txt", ".github/workflows/ci.yml"),
        "bought": "Proof that 'green' had been an inference from local runs. The dependency gap was "
                  "invisible locally precisely because every machine that ran the gates had already "
                  "installed what the gates needed.",
        "bought_grade": F.INFERRED,
        "cost": "Two releases were called green while nothing had verified them off-machine.",
        "cost_grade": F.CONFIRMED,
    },
    {
        "key": "D2",
        "title": "A tag one commit behind main",
        "phase": "tag",
        "what": "v0.13.3 was tagged, then a README typo fix landed. The tag pointed at the commit "
                "before the fix and the README read as current, so the published release and the "
                "branch disagreed by one commit.",
        "found": "By naming the loose end in the summary and then checking it, not by any gate.",
        "fix": "`tools/release_state.py` compares HEAD, the newest tag, the newest CI run, the Pages "
               "build and the newest release, and exits non-zero when they disagree. Its first run "
               "also found that three tags (v0.13.1, v0.13.2, v0.13.3) had no release objects at "
               "all, so /releases stopped at v0.11.0.",
        "artifacts": ("tools/release_state.py",),
        "bought": "The phase boundary became explicit: every gate runs before the tag exists, so the "
                  "push that creates drift is the push the gates cannot see. The checker lives after "
                  "the tag on purpose, and the operating model now says so.",
        "bought_grade": F.INFERRED,
        "cost": "For one release, the advertised state and the tagged state were different.",
        "cost_grade": F.CONFIRMED,
    },
    {
        "key": "D3",
        "title": "Three links that only worked on the site",
        "phase": "publish",
        "what": "The security report linked to sibling pages by published slug (`limitations.html`). "
                "That resolves on the static site, because `docs/` contains those files, and 404s in "
                "the repository, which does not.",
        "found": "The external citation check, on the first CI run of the report. Nothing local saw "
                 "it: the internal check walks published pages, where the targets exist.",
        "fix": "Links name the Markdown source, which the builder rewrites to a slug for the site and "
               "the repository resolves as a file, so one href is correct in both places. A test "
               "refuses a relative `.html` link in a report.",
        "artifacts": ("qvault/tests/test_security_report.py",),
        "bought": "Evidence that the external check earns its place, and a map of the internal "
                  "check's blind spot: it validates the artefact, not the source.",
        "bought_grade": F.INFERRED,
        "cost": "v0.13.6 shipped red and was superseded by v0.13.7 the same day.",
        "cost_grade": F.CONFIRMED,
    },
    {
        "key": "D4",
        "title": "A gate fighting its own generators",
        "phase": "tree",
        "what": "Gate G16 required aligned tables. The tables were padded, and then every generator "
                "reported itself stale, because padding the files while `render()` still emitted "
                "ragged rows makes the comparison fail the other way.",
        "found": "By reading the gate failures in order instead of padding again.",
        "fix": "Padding moved into `tools/tables.py` and every generator renders through it, so the "
               "source is aligned before the comparison runs.",
        "artifacts": ("tools/tables.py",),
        "bought": "The general rule, now applied to every gate: when the input is generated, enforce "
                  "at the generator, not at the file.",
        "bought_grade": F.INFERRED,
        "cost": "A gate that was green on the artefact and red on the source for part of an afternoon.",
        "cost_grade": F.CONFIRMED,
    },
    {
        "key": "D5",
        "title": "Grade arithmetic that returned the stronger answer",
        "phase": "tree",
        "what": "`_lower` in the denial model returned the stronger of two grades, and the proposal "
                "ladder topped out at INFERRED, so the CORROBORATED ceiling was unreachable and "
                "in-band enforcement graded identically to a hardware plane.",
        "found": "By printing a matrix of posture x plane x evidence and reading it. The tests "
                 "written alongside it shared its mental model and all passed.",
        "fix": "Rank comparison corrected and the ladder extended to CORROBORATED. Gate G17 now "
               "sweeps every combination rather than trusting a handful of examples.",
        "artifacts": ("qvault/denial.py",),
        "bought": "The most useful lesson in this log: a test written from the same mental model as "
                  "the bug will agree with the bug. The sweep exists because examples did not.",
        "bought_grade": F.INFERRED,
        "cost": "For the length of one generation cycle, the model graded a weak control as strong.",
        "cost_grade": F.CONFIRMED,
    },
    {
        "key": "D6",
        "title": "Numbers in prose, maintained by hand",
        "phase": "publish",
        "what": "Changelog and README carried hand-typed counts: a placeholder '82x tests' left in a "
                "commit, and 'all sixteen gates' while the seventeenth already existed.",
        "found": "Reading the file after the number had changed, which is the only way this class "
                 "is ever found.",
        "fix": "Counts that must be right are generated or omitted. The security report states the "
               "gate count from the gate registry and refuses to state a test count it cannot read.",
        "artifacts": ("tools/gen_security_report.py",),
        "bought": "A rule with teeth: a number in a generated document is checked by construction, "
                  "and a number in hand-written prose is an assertion with no owner.",
        "bought_grade": F.INFERRED,
        "cost": "Two documents published a count that was wrong when written.",
        "cost_grade": F.CONFIRMED,
    },
)


def census() -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in EVENTS:
        counts[event["phase"]] = counts.get(event["phase"], 0) + 1
    return counts


def render() -> str:
    phases = census()
    out = [f"# Defect log: what the red runs bought\n\n"]
    out.append(f"Release **{__version__}**. This page is the engineering record of this project's own\n"
               "failures, graded with the same vocabulary it uses on malware claims. A project whose\n"
               "thesis is *do not promote absence and do not overstate* has no honest way to show a\n"
               "green badge without showing what red taught it.\n\n")
    out.append(
        "> **How to read the grades here.** `CONFIRMED` means the artefact exists: a commit, a CI run,\n"
        "> a file in this repository. `INFERRED` marks the causal claim that a fix prevents its class\n"
        "> of defect, which is a prediction and not an observation. Nothing on this page is graded\n"
        "> above what its evidence supports, including the sentences about how useful the mistakes\n"
        "> turned out to be.\n\n")

    out.append("## The finding, before the list\n\n")
    out.append(
        f"Six defects, and five of them lived on a boundary rather than in the code: the tree, the\n"
        f"push, the tag, the publish. Phases: tree {phases.get('tree', 0)}, push {phases.get('push', 0)}, "
        f"tag {phases.get('tag', 0)}, publish {phases.get('publish', 0)}.\n\n")
    out.append(
        f"The gates were sound and still let a broken release out. All {len(gates.GATES)} of them run\n"
        "inside one phase, on the author's machine, before the thing they would need to inspect\n"
        "exists. A check cannot catch a defect in a boundary it does not cross. That is the whole\n"
        "finding, and most of the fixes below are an instance of it.\n\n")

    for event in EVENTS:
        out.append(f"## {event['key']} - {event['title']}\n\n")
        out.append(f"**Phase.** {event['phase']}\n\n")
        out.append(f"**What happened.** {event['what']}\n\n")
        out.append(f"**How it was found.** {event['found']}\n\n")
        out.append(f"**What fixed it.** {event['fix']}\n\n")
        out.append(f"**What it bought.** {event['bought']}\n\n")
        out.append(f"*Grade of that claim: {event['bought_grade']}.*\n\n")
        out.append(f"**What it cost.** {event['cost']} *({event['cost_grade']}).*\n\n")

    out.append("## The counterfactual that matters\n\n")
    out.append(
        "The useful question is not how each defect was fixed, it is whether a reader would have\n"
        "known. For D1 and D2 the answer is no: a green claim and a current-looking README sat over\n"
        "states that were neither. For D3 the answer is yes, within minutes, because the external\n"
        "check disagreed with the author's machine. That asymmetry is why the fixes are checks and\n"
        "not resolutions.\n\n")
    out.append(
        "The defects that would have stayed hidden are the ones worth the most here. A defect caught\n"
        "by the tool that already existed costs an afternoon; a defect that only an absent check\n"
        "would have caught is a claim that was false in public.\n\n")

    out.append("## What the mistakes transferred\n\n")
    out.append("Three things that outlived the individual fixes:\n\n")
    out.append("1. **Each fix became a check, not a resolution.** `release_state.py` for the tag phase, "
               "the external citation check now trusted for links, G16 at the generator, G17 as a "
               "full sweep, a pinned dev dependency. A fixed defect with no check behind it returns.\n")
    out.append("2. **The phase model is now explicit.** Push-time gates cannot see post-tag state, so "
               "the release phase has its own verification instead of being assumed.\n")
    out.append("3. **Grading the project's own prose became normal.** The security report refuses to "
               "state a number it cannot read, and this page grades its own claims about usefulness.\n\n")

    out.append("## The two sources that still refuse automation\n\n")
    out.append(
        "Two cited sources answer 403 to automated clients: a DoD mitigation guide and an ISO\n"
        "catalogue page. They are recorded as blockers rather than dropped, because *our client was\n"
        "refused* is not *the source is gone*. They are the honest residual: the citation check is\n"
        "green with those two marked, not green because they were waived.\n\n")

    out.append("## What this page does not claim\n\n")
    out.append(
        "It does not claim the project is now free of this class of defect. It claims that six\n"
        "specific defects are fixed, that each has a check behind it, and that the checks live on\n"
        "the side of the boundary where the defect appeared. A seventh defect of the same shape may\n"
        "still be sitting in a phase nobody has instrumented yet.\n\n")
    out.append(
        "It also does not claim the defects were worth it. The benefit is graded INFERRED for a\n"
        "reason: the counterfactual (what the same effort buys without the mistake) cannot be\n"
        "observed, only argued.\n")
    return "".join(out)


def main() -> int:
    OUT.write_text(tables.align(render()))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

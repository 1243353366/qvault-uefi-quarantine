# Defect log: what the red runs bought

Release **0.16.0**. This page is the engineering record of this project's own
failures, graded with the same vocabulary it uses on malware claims. A project whose
thesis is *do not promote absence and do not overstate* has no honest way to show a
green badge without showing what red taught it.

> **How to read the grades here.** `CONFIRMED` means the artefact exists: a commit, a CI run,
> a file in this repository. `INFERRED` marks the causal claim that a fix prevents its class
> of defect, which is a prediction and not an observation. Nothing on this page is graded
> above what its evidence supports, including the sentences about how useful the mistakes
> turned out to be.

## The finding, before the list

Six defects, and five of them lived on a boundary rather than in the code: the tree, the
push, the tag, the publish. Phases: tree 2, push 0, tag 1, publish 3.

The gates were sound and still let a broken release out. All 17 of them run
inside one phase, on the author's machine, before the thing they would need to inspect
exists. A check cannot catch a defect in a boundary it does not cross. That is the whole
finding, and most of the fixes below are an instance of it.

## D1 - CI was declared before it ever ran

**Phase.** publish

**What happened.** The badge, the workflow file and the claim that CI runs the suite were all in the README while the workflow had never executed: the OAuth token lacked the `workflow` scope, so the push carrying `ci.yml` was rejected. The badge was removed rather than left implying a run that did not exist.

**How it was found.** A push that failed to carry the file, checked instead of assumed.

**What fixed it.** The scope was authorized, the workflow landed, and the first real run went red on a missing dependency (`markdown`, absent from the lock file but present in every developer venv). `requirements-dev.txt` now pins it.

**What it bought.** Proof that 'green' had been an inference from local runs. The dependency gap was invisible locally precisely because every machine that ran the gates had already installed what the gates needed.

*Grade of that claim: INFERRED.*

**What it cost.** Two releases were called green while nothing had verified them off-machine. *(CONFIRMED).*

## D2 - A tag one commit behind main

**Phase.** tag

**What happened.** v0.13.3 was tagged, then a README typo fix landed. The tag pointed at the commit before the fix and the README read as current, so the published release and the branch disagreed by one commit.

**How it was found.** By naming the loose end in the summary and then checking it, not by any gate.

**What fixed it.** `tools/release_state.py` compares HEAD, the newest tag, the newest CI run, the Pages build and the newest release, and exits non-zero when they disagree. Its first run also found that three tags (v0.13.1, v0.13.2, v0.13.3) had no release objects at all, so /releases stopped at v0.11.0.

**What it bought.** The phase boundary became explicit: every gate runs before the tag exists, so the push that creates drift is the push the gates cannot see. The checker lives after the tag on purpose, and the operating model now says so.

*Grade of that claim: INFERRED.*

**What it cost.** For one release, the advertised state and the tagged state were different. *(CONFIRMED).*

## D3 - Three links that only worked on the site

**Phase.** publish

**What happened.** The security report linked to sibling pages by published slug (`limitations.html`). That resolves on the static site, because `docs/` contains those files, and 404s in the repository, which does not.

**How it was found.** The external citation check, on the first CI run of the report. Nothing local saw it: the internal check walks published pages, where the targets exist.

**What fixed it.** Links name the Markdown source, which the builder rewrites to a slug for the site and the repository resolves as a file, so one href is correct in both places. A test refuses a relative `.html` link in a report.

**What it bought.** Evidence that the external check earns its place, and a map of the internal check's blind spot: it validates the artefact, not the source.

*Grade of that claim: INFERRED.*

**What it cost.** v0.13.6 shipped red and was superseded by v0.13.7 the same day. *(CONFIRMED).*

## D4 - A gate fighting its own generators

**Phase.** tree

**What happened.** Gate G16 required aligned tables. The tables were padded, and then every generator reported itself stale, because padding the files while `render()` still emitted ragged rows makes the comparison fail the other way.

**How it was found.** By reading the gate failures in order instead of padding again.

**What fixed it.** Padding moved into `tools/tables.py` and every generator renders through it, so the source is aligned before the comparison runs.

**What it bought.** The general rule, now applied to every gate: when the input is generated, enforce at the generator, not at the file.

*Grade of that claim: INFERRED.*

**What it cost.** A gate that was green on the artefact and red on the source for part of an afternoon. *(CONFIRMED).*

## D5 - Grade arithmetic that returned the stronger answer

**Phase.** tree

**What happened.** `_lower` in the denial model returned the stronger of two grades, and the proposal ladder topped out at INFERRED, so the CORROBORATED ceiling was unreachable and in-band enforcement graded identically to a hardware plane.

**How it was found.** By printing a matrix of posture x plane x evidence and reading it. The tests written alongside it shared its mental model and all passed.

**What fixed it.** Rank comparison corrected and the ladder extended to CORROBORATED. Gate G17 now sweeps every combination rather than trusting a handful of examples.

**What it bought.** The most useful lesson in this log: a test written from the same mental model as the bug will agree with the bug. The sweep exists because examples did not.

*Grade of that claim: INFERRED.*

**What it cost.** For the length of one generation cycle, the model graded a weak control as strong. *(CONFIRMED).*

## D6 - Numbers in prose, maintained by hand

**Phase.** publish

**What happened.** Changelog and README carried hand-typed counts: a placeholder '82x tests' left in a commit, and 'all sixteen gates' while the seventeenth already existed.

**How it was found.** Reading the file after the number had changed, which is the only way this class is ever found.

**What fixed it.** Counts that must be right are generated or omitted. The security report states the gate count from the gate registry and refuses to state a test count it cannot read.

**What it bought.** A rule with teeth: a number in a generated document is checked by construction, and a number in hand-written prose is an assertion with no owner.

*Grade of that claim: INFERRED.*

**What it cost.** Two documents published a count that was wrong when written. *(CONFIRMED).*

## The counterfactual that matters

The useful question is not how each defect was fixed, it is whether a reader would have
known. For D1 and D2 the answer is no: a green claim and a current-looking README sat over
states that were neither. For D3 the answer is yes, within minutes, because the external
check disagreed with the author's machine. That asymmetry is why the fixes are checks and
not resolutions.

The defects that would have stayed hidden are the ones worth the most here. A defect caught
by the tool that already existed costs an afternoon; a defect that only an absent check
would have caught is a claim that was false in public.

## What the mistakes transferred

Three things that outlived the individual fixes:

1. **Each fix became a check, not a resolution.** `release_state.py` for the tag phase, the external citation check now trusted for links, G16 at the generator, G17 as a full sweep, a pinned dev dependency. A fixed defect with no check behind it returns.
2. **The phase model is now explicit.** Push-time gates cannot see post-tag state, so the release phase has its own verification instead of being assumed.
3. **Grading the project's own prose became normal.** The security report refuses to state a number it cannot read, and this page grades its own claims about usefulness.

## The two sources that still refuse automation

Two cited sources answer 403 to automated clients: a DoD mitigation guide and an ISO
catalogue page. They are recorded as blockers rather than dropped, because *our client was
refused* is not *the source is gone*. They are the honest residual: the citation check is
green with those two marked, not green because they were waived.

## What this page does not claim

It does not claim the project is now free of this class of defect. It claims that six
specific defects are fixed, that each has a check behind it, and that the checks live on
the side of the boundary where the defect appeared. A seventh defect of the same shape may
still be sitting in a phase nobody has instrumented yet.

It also does not claim the defects were worth it. The benefit is graded INFERRED for a
reason: the counterfactual (what the same effort buys without the mistake) cannot be
observed, only argued.

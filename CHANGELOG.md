# Changelog

All notable changes to qvault. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Evidence grades appear throughout: **CONFIRMED**, **CORROBORATED**, **INFERRED**,
**HYPOTHESIS**, **UNKNOWN**. See `report/EVIDENCE_POLICY.md` for what they mean and what
they deliberately do not mean.

---

<<<<<<< HEAD
## [Unreleased] - feature/cdup

### Added - CDUP, kept off main

Cryptographic Data Usability Protection: assume the payload is stolen, minimise what the thief can
recover. A fresh DEK per object, AES-256-GCM per chunk with the AAD bound to the object id, and the
DEK wrapped under a KEK held by a separate authority that mints short-lived, single-use, audited
capabilities. The store holds no key material; `assert_separated` refuses an authority nested inside
the store it protects.

Thirteen tests are written from the attacker's side. Expired, forged, replayed and wrong-object
capabilities all return the same bytes, and a test asserts that.

Not addressed, and stated as such on the page: everything before encryption (keylogger, screen
capture) and plaintext in memory during use. The boundary is deployment - an authority on the same
host that answers whatever asks is an envelope, not a boundary.

Held off `main` until the legal reading was settled, then merged; the branch history stays in git.
=======
## [0.15.0] - 2026-11-02

### Added - records sealed at rest, seven properties

`qvault/atrest.py`: AES-256-GCM with the record id bound in the associated data, wrapped per-record
DEKs in a separate key root, a hash-linked chain over content identity, append-only writes, rotation
that re-wraps without touching ciphertext, revocation that destroys availability without touching
data, and a write path that raises and leaves nothing behind when sealing is impossible.

Honest limits, on the page rather than in a footnote: TPM backing is graded HYPOTHESIS (no attestation
captured, and no device in this environment); the software protector must be requested explicitly and
is defeated by a read of its key root; plaintext lives in process memory during seal and after open.

Three bugs the tests found: the key id was bound into the payload's AAD, which made rotation
impossible; the head file stored a count where a sequence number belonged, so every record claimed
seq 0; and the chain hashed whole envelopes, so rotation broke every link.

## [0.14.0] - 2026-11-02

### Added - CDUP, kept off main

Cryptographic Data Usability Protection: assume the payload is stolen, minimise what the thief can
recover. A fresh DEK per object, AES-256-GCM per chunk with the AAD bound to the object id, and the
DEK wrapped under a KEK held by a separate authority that mints short-lived, single-use, audited
capabilities. The store holds no key material; `assert_separated` refuses an authority nested inside
the store it protects.

Thirteen tests are written from the attacker's side. Expired, forged, replayed and wrong-object
capabilities all return the same bytes, and a test asserts that.

Not addressed, and stated as such on the page: everything before encryption (keylogger, screen
capture) and plaintext in memory during use. The boundary is deployment - an authority on the same
host that answers whatever asks is an envelope, not a boundary.

Held off `main` until the legal reading was settled, then merged; the branch history stays in git.

### Added - threat intelligence where the doctrine is code

Three questions kept apart: what software is operating, what infrastructure it depends on, how the
operation finances itself. `qvault/threatintel.py` collects graded observations, computes what they
support from provenance rather than row count, and refuses the rest.

Enforced rather than documented: collection sources (probe, forced rotation, credential use,
purchase, wallet interaction, intrusion) are refused on intake and the module has no network code at
all; per-claim ceilings cap operator, wallet and proxy attribution at HYPOTHESIS, with no identity
field in the output; four observations derived from one report count once; `disruption_plan` emits
report/notify/preserve/submit against named channels and refuses any other verb. A package without a
competing explanation per hypothesis is refused.

Also: `deleted_domains_are_not_enough` reports ledger-pointer dependency, so a domain takedown is not
mistaken for a fix, and returns UNKNOWN rather than clean when no pointer is seen.

Two self-inflicted bugs found by the tests: a derived observation hashed to its parent's id, so the
provenance walk followed itself and the test **hung instead of failing** (identity now covers every
field, and cycles are refused). Twenty-four tests, written from the analyst's side.

Held off `main` while under review, merged in this release: naming wallets and channels is a
different publication from quarantining firmware, so it was settled deliberately.

### Added - evidence brief for filing

`qvault/evidence_brief.py` builds a custody-grade brief: per-artefact SHA-256 recomputed from bytes,
acquisition time with a mandatory timezone, acquiring party, documented method, source provenance,
immutability checked from the mode bits, a timeline, computed attribution grades, the hypothesis
carried as a hypothesis beside a required competing explanation, and a manifest hash that
`verify` recomputes.

Refusal is the design. A hash mismatch, a naive or future timestamp, an undocumented acquisition
method, an unattributed artefact, a missing original, a writable original, a self-declared
CORROBORATED grade, a missing alternative, or a hypothesis that names a person all stop the brief.
No `owner`, `identity` or `suspect` field exists in the structure, so a name cannot be written beside
an artefact.

Two checks that were quietly broken, both found here: `os.access(W_OK)` is True for a 0400 file as
root, so the immutability check passed on everything in a container and now reads mode bits; and git
preserves no mode but the exec bit, so a committed example artefact would arrive writable and be
correctly refused, hence the demo case stays local.

Nineteen tests, plus a CLI that exits 2 and says "refused" rather than writing a defective document.

### Added - input capture graded by observation point

`qvault/inputcapture.py` classifies collection mechanisms into four tiers - application, OS,
privileged, external - and keeps **severity on a separate axis**, because a level 1 session thief
routinely costs more than a level 3 keylogger. Level 4 is listed and marked unobservable from the
host rather than omitted; confirming it needs external instrumentation.

Corroboration requires two distinct telemetry planes; three signals from one plane are one
observation. Every innocent explanation recorded for these signals (accessibility tools, keyboard
utilities, remote support, vendor input drivers) must be excluded on the record before corroboration.
`CONFIRMED` is unreachable, and an empty case is `UNKNOWN` with a caveat, never clean.

Bug found by a test: the case grade was computed with `min` over grade ranks, which returned the
**strongest** technique - a case with one corroborated and one inferred finding reported
CORROBORATED overall. Now the weakest, as it must be.
>>>>>>> feature/threatintel

## [0.13.12] - 2026-11-02

### Fixed - the two riskiest rows, hardened and re-graded

`store.py` and `audit.py` were the two entries in `report/TOOLING_RISK.md` that trust data written by
an adversary who knows it is being collected. Both now refuse attacks that were previously only
described.

**store.py** opens every read with `O_NOFOLLOW`, `O_NONBLOCK` and an `S_ISREG` check, so a symlink
where an object should be is refused rather than followed to `/etc/shadow`, and a FIFO is refused
rather than blocking the reader forever. An object chmod'd group- or world-writable after seal is
refused, ids cannot traverse, and `seal_object` fsyncs the directory so a crash cannot lose the link
while keeping the bytes.

**audit.py** keeps its hash chain and signed checkpoint, and adds a persisted high-water mark that
refuses to append to a log shorter than the last recorded count. That closes the specific attack
`verify()` could never see: truncate the head, then keep appending so the log looks continuous. The
log is also opened without following a symlink.

Nine new tests build each attack and assert the refusal: symlink, FIFO, widened mode, traversal,
truncate-then-append, symlinked log, plus a regression that a valid object and chain still work.

What is **not** closed, and is now written in the register rather than implied: the store refuses a
link and a widened mode but not a regular 0400 file an attacker substituted, so content integrity is
still the envelope hash plus the chain. And both audit controls live on the same volume, so an
attacker who rewrites the mark and the log together, or holds the signing key, defeats both; only an
off-box anchor closes that, and that is deployment, not code.

## [0.13.11] - 2026-11-02

### Added - the four risks get a section on the front door

The risk documents existed and were linked from a policy line; the README still opened with a status
warning that said only "prototype". It now carries `## The risks of running this` between the status
warning and the architecture: a modified copy, the tool as an attack surface, claims outrunning
evidence, and undocumented behaviour as exposure, each pointing at the file that treats it.

A test holds the section in place and fails if any of the four references or the two honest
sentences disappear: tags are not signed, and nothing has been fuzzed.

One self-correction inside the edit: the first draft put the unverified ledger count in the README as
a typed number. That is defect D6 in the middle of documenting defects, so the count came out and the
sentence states the fact without a figure that would drift.

## [0.13.10] - 2026-11-02

### Added - the four risks of publishing this, answered in files

Publishing a tool that parses hostile firmware creates four exposures that code alone does not
address. Each now has a document, and the documents are checkable where they can be.

**A copy can be modified or repackaged.** `PROVENANCE.md` states the Apache-2.0 obligations that
travel with a redistribution (LICENSE, NOTICE, CREDITS), what a fork may and may not imply, and how
to verify a release: wheel plus `SHA256SUMS` on the release page, commit hash, public CI run. It
also states the limit plainly: tags are **not signed**, no signing key is configured, so integrity
rests on HTTPS to GitHub and the commit hash rather than on a signature.

**The tooling is itself an attack surface.** `report/TOOLING_RISK.md` registers every component that
consumes input it does not control, with the guard found by reading it and the gap that remains.
Three rows say `none observed` because no bound was found, and the page says so rather than
describing intent. A test fails if a module takes `bytes` or parses JSON and is not registered.

**Claims can outrun their evidence.** `CONTRIBUTING.md` makes a claim a row, not a sentence: source,
locator, tag and falsifier, with `CONFIRMED` requiring independent verification and hardware-plane
claims requiring an out-of-band anchor. It lists what gets rejected, including `CLEAN` from missing
telemetry and any offensive capability.

**Behaviour can be poorly documented.** `SECURITY.md` routes reports to private advisories, states
that there is no bounty and no response SLA, and splits in-scope (parsers, store, audit chain, key
handling, denial responses) from out of scope (the implant families, remediation claims, anything
requiring kernel control, which is the documented host trust gap).

Twenty-six new tests across the register and the policies.

## [0.13.9] - 2026-11-02

### Added - discovery files, with the caveat in the file

`docs/sitemap.xml` and `docs/robots.txt`, both generated by `tools/build_docs.py` from the page
registry, so a new page cannot be published and forgotten. Six tests: every page present, absolute
URLs, well-formed XML, no `lastmod` (a clock in a generated file would make the docs-drift gate
meaningless), and robots.txt advertising the sitemap.

`robots.txt` says in its own body that it is advisory at this path. RFC 9309 has a crawler fetch
`/robots.txt` at the origin root, once per origin; on `github.io` that origin is shared and the
project cannot write it. The file is published so the policy travels with the site and the sitemap
sits at a stable path, not because it will be the file a crawler reads. The sitemap is the part
that actually helps discovery, and submitting it still requires the owner in Search Console.

## [0.13.8] - 2026-11-02

### Added - the defect log, and the README says what went wrong

`report/DEFECT_LOG.md`, generated by `tools/gen_defect_log.py`: six of this project's own defects,
each with how it was found, what fixed it, what it bought and what it cost, graded with the same
vocabulary the project uses on malware claims.

The finding is not the list. Five of the six lived on a phase boundary (tree, push, tag, publish)
rather than in the code, and every gate runs inside one phase on the author's machine before the
thing it would need to inspect exists. The gates were sound and still let a broken release out.

Two things are graded deliberately: the benefit of each mistake is INFERRED, because "this fix
prevents that class" is a prediction, and the cost is CONFIRMED where an artefact exists. The page
does not claim the class is extinct.

The README now carries the same account in four sentences, next to the status warning, instead of
leaving it in commit messages. It also stops saying "sixteen gates" a release after the
seventeenth existed, which is defect D6 describing itself.

I first wrote a test count in this entry and it was wrong by two, which is the same defect a third
time; the count is gone rather than corrected. A number that must be right belongs in a generated
document, not in prose.

## [0.13.7] - 2026-11-02

### Fixed - three links that only worked on the site

The security report linked to its sibling pages by published slug: `limitations.html`,
`denial-model.html`, `citations.html`. That resolves on the static site, because `docs/` contains
those files, and 404s in the repository, which does not. The internal link check walks published
pages, so it saw nothing wrong; the external citation check resolved the same hrefs against the
repository and reported three broken links on the first CI run.

Links now name the Markdown source. The builder rewrites it to the page slug for the site, and the
repository resolves it as a file, so one href is correct in both places. A test refuses a relative
`.html` link in the report.

External citations now read 74 unique (72 answering, 2 blocked, 0 broken). The two that answer 403
to automated clients - a DoD PDF and an ISO catalogue page - are recorded as blockers in
`tools/linkcheck.py` rather than dropped, because "our client is refused" is not "the source is
gone".

827 tests, seventeen gates.

## [0.13.6] - 2026-11-02

### Added - the security report for this release

`report/SECURITY_REPORT.md`, generated by `tools/gen_security_report.py`. A point-in-time report
that reads its own numbers: the gate list, the claims census and the posture ceilings are taken
from the tree at build time, because a security report that drifts from the code it describes is
worse than none. Ten tests hold it to that, including one that fails the build if the census in the
document stops matching `CLAIMS_LEDGER.csv`.

It reports the uncomfortable line as a line: of 172 ledger claims, 51 carry no independent
verification. It also lists six open findings with a grade and a falsifier each - the host trust
gap, the self-scan limit, missing identity binding for dual control, two hardware hypotheses that
emulation cannot settle, and the boundary of retroactive encryption.

`assert_no_overclaim` refuses the phrases a document like this drifts into ("guarantees", "proves
the absence", "is malware-free"), so the reassurance cannot be edited in.

826 tests, seventeen gates.

## [0.13.5] - 2026-11-02

### Added - the denial model, with the failures included

Three postures, kept apart because they fail differently: `deny_access` (the payload is
unusable), `deny_capability` (the code cannot reach what it needs), `deny_execution` (the code
exists but cannot start). `qvault/denial.py` and the generated
`report/DENIAL_MODEL.md`.

Each posture carries what it does **not** do, which is the useful half:

- encryption denies access only while the key is withheld, and ends the moment the key returns
  inside the attacker's reach; a key copied before encryption was never denied at all, and a
  bootkit in SPI flash needs no payload to decrypt
- isolation removes only what is on our enumeration, and a quiet implant on an isolated host is
  quieter rather than absent
- an allow list denies execution only where the verification root is outside the code being
  verified; a signed-but-hostile component passes by construction, and a revocation nobody shipped
  denies nothing

Grade arithmetic: the enforcement plane sets the ceiling (hardware, external key, out of band and
applied revocation reach CORROBORATED; in-band policy caps at INFERRED; no plane at all is
UNKNOWN), and **no denial claim reaches CONFIRMED**, because inability is inferred from the absence
of a success and absence of evidence is not evidence. Gate G17 refuses a plane that claims
CONFIRMED and refuses a posture that has lost its non-claims.

23 tests in `qvault/tests/test_denial.py`. 814 tests, seventeen gates.

## [0.13.4] - 2026-11-02

### Added - a way to ask whether the release, the remote and the site agree

v0.13.3 was tagged, then one more commit landed, so the tag pointed a commit behind main while the
README read as current. Nothing caught it, because every gate runs before the tag exists: the push
that creates drift is the push the gates cannot see.

`tools/release_state.py` is the post-release counterpart. It compares local HEAD, the newest tag,
the newest CI run, the Pages build and the newest published release, and exits non-zero when they
disagree. It is deliberately not a gate - it needs the network and a pushed tag, so its place is
after a release, not before a push.

### Fixed - releases existed only up to v0.11.0

`v0.13.1`, `v0.13.2` and `v0.13.3` had tags but no release objects, so `/releases` stopped at
v0.11.0 while the site advertised 0.13.x. All three are published from their changelog sections.

## [0.13.3] - 2026-11-02

### Added - CI actually runs

The `workflow` scope was the missing piece: GitHub refuses workflow files from a token without
it, and the file had also been sitting in `.git/info/exclude`, so "we have CI" was never true.
With the scope granted, `.github/workflows/ci.yml` is pushed and live: tests on 3.11 and 3.12,
all sixteen gates, docs-drift, both link checks, the wheel install and static analysis, every step
under `set -o pipefail`.

The package job was rehearsed locally before the push, because a red first run is worse than no
badge: the wheel builds, the vendored detector travels in it, `qvault --version` and
`qvault enclave` work from an installed wheel outside the checkout, and `ruff --select E9,F63,F7,F82`
is clean.

### Fixed - tables line up in the source

`tools/tables.py` pads every markdown table to its column widths, and gate G16 fails a document
whose tables are ragged. The point is the diff, not the rendering: a rendered table hides ragged
pipes, so a hand-edited row used to look fine in review and misalign in the source.

This needed the generators fixed, not just the files: padding the outputs while the emitters kept
producing ragged rows made four generators report themselves stale, and the gates comparing
`render()` rather than aligned output failed the same way. `gen_behavior_matrix`,
`gen_telemetry_map`, `gen_in_the_wild` and `gen_fingerprints` now emit aligned tables, the gates
compare aligned output, and `tools/fix_tables.py --write` repairs any file by hand.

791 tests, sixteen gates.

**The first run was red, and the second was green.** Every job installed
`requirements-lock.txt`, which carries the runtime deps and pytest but not `markdown`, so
`test_docs` and G12 had no renderer. `requirements-dev.txt` now pins markdown, build and ruff
against the versions the gates were verified with. With that, all six jobs pass, and the badge is
back in the README - it was removed earlier precisely because nothing was behind it.

## [0.13.2] - 2026-11-02

### Fixed - BlackLotus was being described as a firmware implant

The generated control table was identical for all three families, so BlackLotus inherited
"firmware written from the running OS" and "out-of-band SPI read against a vendor reference".
Neither applies. BlackLotus keeps files on the EFI System Partition and defeats Secure Boot by
chaining through a signed-but-vulnerable bootloader; an SPI read finds nothing, and a clean result
would have been read as exoneration. The rows are now generated from substrate.

`qvault/residency.py` holds the taxonomy: LoJax and MoonBounce in SPI flash (survive disk wipe and
OS reinstall, found only out of band, removed only by reflash, revocation insufficient),
BlackLotus on the ESP (survives reinstall that keeps the ESP, removed by ESP rebuild plus
`dbx`/SVN revocation, where revocation is an effective control). `assert_taxonomy()` refuses a
table that offers an SPI read for an ESP-resident family, and `conflation_claims()` flags prose
that places one in flash - explicitly negated statements excepted.

### Added - acquisition and analysis boundaries

`report/ACQUISITION_AND_ANALYSIS.md`: work from a dump rather than a live infected board, acquire
with an external SPI programmer because in-OS readers can be answered by the implant, diff against
a clean vendor image for the exact board, carve with UEFITool NE or `uefi-firmware-parser`,
disassemble in Ghidra with an EFI loader or IDA with efiXplorer, keep the analysis box air-gapped,
and own a programmer and a verified known-good image before touching hardware. It also states
what this project will not produce, and that a machine you suspect is infected is a containment
problem first and an analysis problem second.

### Added - the emulator boundary (A5)

QEMU/OVMF does not reproduce `BIOS_CNTL`, the protected range registers, the SPI descriptor or SMM
locking, so a write that hardware blocks succeeds in a guest. A write-protection conclusion
reached only under emulation is a HYPOTHESIS regardless of how often the test passes.

### Gates and tests

G15 checks the taxonomy, the generated tables and the prose together. Twenty tests in
`test_residency.py`, including that the control rows differ by substrate and that correct
statements are not flagged. 787 tests, fifteen gates.

## [0.13.1] - 2026-11-02

### Fixed - a gate that fails now stops the push

`.githooks/pre-push` runs all fourteen gates and exits nonzero on any failure; `bash
tools/install_hooks.sh` points a clone at it. The gates already returned 1 on failure. What was
missing was anything listening: a `| tail` in my own command swallowed the exit code and a broken
commit reached main. `tools/reproduce.sh` and the CI workflow run with `set -o pipefail` for the
same reason.

### Added - the version has one source

`qvault/__init__.py` is authoritative. `tools/sync_version.py --check` fails when the README,
packaging metadata, `qvault --version` or the newest changelog heading disagree with it. Gate G13
runs that check. This is the README-at-0.5.0 bug turned into a test: the copy went stale because
nothing compared it to the code. CHANGELOG history and `vendor/` are exempt, with reasons stated
in the tool.

### Added - link checking, internal and external

`tools/linkcheck.py --internal` resolves every href in the published site offline (448 links
across 20 pages) and is gate G14. `--external` probes each cited URL and separates a dead link
from a host that refuses automated clients. Run for the first time, it found:

- **Three Microsoft symbol-store URLs returning 404**, printed in the BlackLotus section as
  though they were retrievable evidence. The identifier pairs could not be verified, so they are
  replaced by the documented pattern plus a note. An unverifiable identifier presented as evidence
  is worse than the pattern it illustrates.
- **The CI badge pointed at a workflow that did not exist** (404). Removed rather than left as
  decoration.
- Two citations blocked by policy rather than broken (`media.defense.gov`, `iso.org`), now
  classified as blocked with the reason recorded.

### Fixed - the changelog had one heading for eight releases

Every release note since 0.5.0 was appended as a subsection under `[Unreleased]`. Corrected
here, with the earlier structure described rather than silently reshaped, and the newest heading
now checked against the package version.

### Not done - CI is written but not running

`.github/workflows/ci.yml` covers tests on 3.11 and 3.12, the gates, docs drift, both link
checks, the wheel install and static analysis. It cannot be pushed: the file was listed in
`.git/info/exclude`, and the OAuth app pushing here has no `workflow` scope, so GitHub refuses
with "refusing to allow an OAuth App to create or update workflow". Adding the file through the
GitHub web editor, or granting the scope, makes it live. Until then no badge is shown and the
README says why.

765 tests, fourteen gates.

**On structure.** Until 0.13.1 every release note was appended as a subsection under a single
`[Unreleased]` heading, so the file had one version heading for eight releases. Entries below the
0.13.1 section are therefore accumulated rather than grouped, and per-release headings begin at
0.13.1. The heading is now checked against the package version by gate G13.

---

## [Unreleased] - policy denial (branch: feature/policy-denial)

The policy matrix said what the settings are. Nothing said what happens to a caller that
asks for something else, so an operator received a settings dict and no way to tell
"refused" from "allowed but empty".

### Added

- `netpolicy.authorize()` returns a verdict carrying structured denials rather than a
  boolean: `DENY_EGRESS`, `DENY_UNSEALED_WRITE`, `DENY_OVERCOLLECTION`,
  `DENY_OVER_RETENTION`, `DENY_INSUFFICIENT_CUSTODY`, `DENY_NO_ATTESTATION`,
  `DENY_UNKNOWN_RESOURCE`.
- Each denial names the requirement, the observation, and the remedy, so a refusal is
  actionable instead of final.
- Unknown resources are refused rather than permitted: a request nobody wrote a rule for
  is not thereby allowed.
- Observations are counts and labels only. No share material, key identifier or
  credential reaches a denial, so the refusal cannot become the leak the oracle tests
  exist to prevent.
- `authorize_all()` aggregates several requests deterministically, so two runs over the
  same inputs diff cleanly.
- 19 tests, including monotonicity against a more permissive policy and a check that a
  denial's text carries no material.

### Fixed - the denial was an oracle

The first version of this denial logic leaked. `DENY_UNKNOWN_RESOURCE` versus
`DENY_INSUFFICIENT_CUSTODY`, plus the echoed resource name, told an unauthenticated caller
that a resource existed and which condition was nearly satisfied. Refusals are now coarse
and byte-identical for a real, a forbidden, and a nonexistent resource; detail requires a
principal with a granted flag, and bulk results do not report counts to unprivileged
callers. Rule-engine tests moved to `_evaluate`, and the public surface is tested for what
it refuses to say.

### Added - trust model enforcement

- `separation.grade_ceiling` and `assert_claim_supported`: a claim above what its evidence
  class can support is refused, naming the class that would be enough. A self-report
  supports no conclusion at all; volume of one class is not a stronger class.
- `pipeline_conflicts` / `assert_pipeline_separated`: one identity may not hold acquisition
  and verification, analysis and verification, or storage and verification.
- `assert_custody_claim`: append-only history cannot be claimed on non-WORM storage.
- `assert_scope`: live capture is refused unless the acquisition path is isolated and
  attested.
- `report/TRUST_MODEL.md` maps all six gaps, marking which are enforced in code, which are
  architectural, and which are deployment properties. Assumption A1 (the principal's detail
  grant is not authenticated here) is stated rather than papered over.

### Fixed - the gaps in the modules that make the claims

- **firmware_integrity**: `grade_for` promoted any anchor with two independent sources
  straight to `CONFIRMED`. Firmware that measured itself, measured twice, came out
  confirmed. Promotion is now capped by the anchor's evidence class:
  `pre_os_measured` stays `HYPOTHESIS` at fifty sources, `oob_flash_read` caps at
  `CORROBORATED`, `os_mediated` stays `UNKNOWN`. Every anchor declares a class.
- **store**: durability is declared, never guessed. `storage_class` reads
  `storage.json` or `QVAULT_STORAGE_CLASS`, defaults to `not_worm`, and refuses an
  unrecognised value rather than treating it as durable. `custody_summary` reports
  whether an append-only claim is supported and why not.
- **retrieve**: approvals are checked before the envelope is touched. Reading the envelope
  first made "no such object" distinguishable from "not approved", so anyone holding an
  object id could enumerate the vault without an approval. Both now return the same
  refusal, proven by a test that fails if the envelope is read early.
- **separation**: `certify_host` is granted to verification only and refused to
  acquisition, analysis and storage; `claim_custody` belongs to analysis and storage and
  not to verification. The duty matrix now covers the certification actions, so `may()`
  answers for them.

18 tests in `test_module_trust.py`, 554 in total.

### Added - policy semantics on the authorization boundary

The cheap, testable half of the trust problem, closed with black-box tests:

- **One public denial code.** `PUBLIC_DENIAL_CODE = policy_denied` is the only code an
  unprivileged caller ever sees. A richer taxonomy would be a partition function: which
  code returned would say whether the resource existed and which gate was close to passing.
- **Uniform unknown handling.** A made-up resource, an empty resource and a genuine
  forbidden one produce byte-identical answers under every policy.
- **Denials are recorded, not returned.** `authorize(..., audit=callable)` receives
  resource, policy, codes and caller; the caller's answer is unchanged by recording.
- **Fail closed.** An evaluator exception denies with the same shape as any other refusal,
  is recorded by exception *type* (never message), and surfaces as
  `DENY_EVALUATION_ERROR` only to an operator.
- **Explicit allowance lattice.** `allowance(policy)` and `at_least_as_permissive` make
  monotonicity a property of a table rather than a belief; a swept test asserts that a
  dominating policy never refuses what a dominated one allows, across every request form.
- 25 tests in `test_policy_semantics.py` (581 total).

### Added - the probe contract (`qvault/probe.py`)

A read-only view of one policy decision, built so it cannot become an attack surface:

- **Passive.** No mutation, no filesystem, no connection, no command execution. Tested by
  importing the module source and asserting it contains no socket, urllib, subprocess,
  eval, exec or open, and by snapshotting `POLICIES` around a batch of probes.
- **Coarse.** `ask(resource)` returns one token: `ALLOW`, `DENY` or `UNKNOWN`.
  `context()` reports the caller's own gates by label. Neither names a resource the caller
  did not supply.
- **Bounded.** `Budget(max_seconds, max_calls)`, one attempt by default, no retries, no
  recursion, no discovery loop. An exhausted budget or a slow evaluation returns `UNKNOWN`.
- **Fail closed.** Any evaluator exception returns `UNKNOWN` after exactly one attempt.
  "I could not observe" never becomes "it is absent".
- **Non-oracular.** Forbidden and nonexistent resources return the same token *and* the
  same work: every gate is evaluated regardless of what was asked, verified by an
  evaluation trace and a loose timing ratio.

### Fixed - uniform evaluation work

`_evaluate` returned early for an unknown resource. The words were uniform; the work was
not, and a difference in work is a timing oracle. Every gate is now computed for every
request. That change surfaced a genuine crash: `requested="minimal"` reached the retention
gate and `int()` threw, so a caller could turn a type error into a 500. Request fields are
now coerced with `_as_int`, and a wrong-typed field yields `DENY_INVALID_REQUEST` with the
requirement and a remedy.

### Changed - token precedence

`UNATTESTED` could never surface: every policy that requires attestation also denies
egress, so a denial always came first. Missing attestation now outranks a denial, because
nothing can be concluded from an evidence class that was never established. The individual
gate verdicts remain visible in `context()`, so the denial is not hidden.

24 tests in `test_probe.py` (605 total).

### Added - autostart surface assessment (`qvault/persistence.py`)

Implements the eleven persistence mechanisms in Daulaguphu, "11 Critical Malware
Persistence Mechanisms" (tech-zealots.com, 7 April 2022) as detection, never as technique.
The module has no code that creates or enables an autostart entry.

- Thirteen catalogue entries covering the article's eleven mechanisms (Run/RunOnce,
  Policies\Explorer\Run, startup folders, scheduled tasks, services and ServiceDll,
  BootExecute, hive loading, BHOs, AppInit_DLLs, DLL search order, plus rootkit, bootkit
  and fileless).
- Seven behavioural signals: user-writable location, unsigned binary, LOLBin proxy,
  encoded command, hidden task, service outside System32, nonstandard BootExecute,
  hive outside config, populated AppInit_DLLs.
- Grading follows the collection basis, not the suspicion: `live_host` is a self-report and
  yields no graded finding, `offline_image` caps at CORROBORATED, `attested_image` at
  CONFIRMED. A ceiling is a limit, not a target.
- Rootkit, bootkit and fileless are marked `not observable` rather than silently clean: a
  snapshot cannot see what hides from it.
- `coverage()` reports observed / not_observed / not_observable and states that a mechanism
  not observed was not thereby shown to be absent. Nothing is ever reported CLEAN.
- Every observation carries a benign twin and a control, enforced by
  `assert_catalogue_integrity()` at import.

### Fixed - BootExecute detection

The first version tested whether the default string appeared in the value, so a payload
appended to `autocheck autochk *` passed as normal. It is now an equality check after
whitespace normalisation, which is what "has any value beyond the default" actually means.

30 tests in `test_persistence.py` (635 total).

### Changed - persistence is a detection matrix, not a flag

Restructured against the contract the source article implies, rather than a generic
"autostart observed" boolean:

- **Descriptors.** Each mechanism is a `Mechanism(id, name, observable_path,
  benign_default, control, predicate, observable)`. `_m()` validates at construction that an
  observable mechanism has a predicate and an unobservable one does not, so a descriptor
  cannot claim detection it does not perform.
- **Four result classes.** `detected`, `benign`, `unknown_not_observable`, `not_observed`.
  One row per mechanism is returned for every snapshot, including mechanisms the snapshot
  never mentioned.
- **No clean state.** `CLEAN_STATES` is empty, `assert_not_clean()` raises on any attempt to
  report one, and `summarise()` carries `clean_state_available: False`.
- **Reviewable detection.** Predicates are separate, named functions (`_boot_execute`,
  `_service`, `_hive`, `_appinit`, `_dll_search_order`) beside the descriptor table that
  says what each mechanism is and what removes it.
- **Row shape is constant.** Every matrix row carries the same keys whatever its result;
  the earlier version only added `benign_readings` when an entry existed, which was a shape
  oracle about the snapshot.

### Added - `qvault/grading.py`, a public grade API

`cap_grade(basis=..., signal_count=..., attestation_state=...)` plus `explain()` for the
reasoning. The persistence layer no longer touches `separation._RANK` and no longer computes
ceilings itself; a test asserts the module source contains neither `_RANK` nor
`grade_ceiling`. Ceilings are derived from the evidence-class table, and an `attested_image`
whose attestation did not verify is downgraded to the offline ceiling before use.

### Added - ledger contract test

Two mistakes were made while writing the previous commit: a URL in the numeric bibliography
column, and a ninth column that shifted `tag` and `verification` out of place. Both were
repaired in the data, and `test_the_claims_ledger_obeys_its_own_contract` now asserts the
header width, every row width, the tag and verification vocabularies, and a numeric-or-n/a
bibliography for independently verified rows.

40 tests in `test_persistence.py` (645 total).

### Added - the wire contract (`contract/verdict.schema.json`, `qvault/contract.py`)

The interface other runtimes are allowed to see, and nothing more:

- One payload: mechanism, basis, attestation state, observed signals and counts, verdict
  token, cap grade, denial codes, remedy, statement.
- **`subject.resource` is always null in a policy payload.** The type has no field in which
  to echo what the caller asked about, so a refusal cannot become a probe about what exists.
  A payload that fills it in is rejected by both validators.
- `denial_codes` is a closed vocabulary with exactly one public value, so no adapter can
  invent a taxonomy that partitions resources by which gate nearly passed.
- Persistence payloads must carry a basis and a cap grade and no denial codes; policy payloads
  must carry neither, because an authorisation answer is not an evidence claim.
- Validation runs in two runtimes: `qvault/contract.py` (no dependencies) and
  `adapters/verdict_lint.mjs` (node). Both reject a payload with no remedy, and the test suite
  asserts the Python constants and the schema enums have not drifted apart.

### Added - pre-merge gates (`tools/gates.py`)

G1 tests, G2 smoke, G3 evidence ledger, G4 wire contract in two runtimes, G5 single owner,
G6 no clean state, G7 denial invariance, G8 scope gate. Merge requires all eight.
`assert_single_owner()` fails if an engine module contains a process, socket or shell call or
imports an adapter; the forbidden tokens are assembled rather than written literally so the
checker does not trip on its own source.

### Fixed - gate G7 compared an allow with a refusal

The denial-invariance sweep included `retention`, which an untrusted policy permits with no
requested value, so the gate reported two shapes and looked like an oracle. It now compares
refusals only, and fails if the sweep produces fewer than two of them.

### Added - `report/OPERATING_MODEL.md`

Scrum for backlog, sprints, acceptance and release gates; explicit gates for architecture,
threat model and evidence. Epics E1-E5 mapped to modules and tests, the polyglot boundary as a
table, and the statement that a red gate moves the release rather than the gate.

24 tests in `test_contract.py` (669 total).

### Added - attacker behaviour to control (`qvault/behaviors.py`)

Seventeen behaviours, each naming its ATT&CK technique, the evidence it leaves, the control
here that answers it, and the limit of that control. Coverage is `implemented` (7),
`partial` (6) or `absent` (4), and `absent` is a normal value.

- Every row resolves to a real module and symbol; `resolve()` raises if it does not, so the
  matrix cannot describe code that no longer exists.
- Every row cites a bibliography number, and a test asserts the cited entry names the same
  ATT&CK identifier the row claims.
- Kernel exploitation, browser sandbox escapes, LPE, WMI subscriptions, fileless execution
  and DLL side-loading are recorded as `absent` rather than implied to be covered.
- `report/THREAT_BEHAVIOR_MATRIX.md` is generated by `tools/gen_behavior_matrix.py`; a test
  and gate G9 fail if the document and the catalogue disagree.

### Added - IFEO, from the source review

`T1546.012` Image File Execution Options injection was in ATT&CK and absent from the
catalogue, so `persistence.ifeo` and an `ifeo_debugger` signal were added: a Debugger value
outside Program Files, or on a security-relevant image, is detected; appcompat shims are the
benign twin. Fourteen mechanisms now.

### Verified - technique identifiers

Each ATT&CK identifier in the bibliography was confirmed by reading the page title, not from
memory. Two consequences: `T1574.001` is now titled *Hijack Execution Flow: DLL*, not the
older "DLL Search Order Hijacking", and `T1574.002` and `T1562.001` could not be verified and
were left out rather than guessed.

### Added - 15 bibliography entries

`44`-`58` in `report/UEFI_Malware_Deep_Dive_Report.md`, one per cited technique, each with
the URL and the reason it is cited.

15 tests in `test_behaviors.py` (684 total), gate G9 added.

### Added - telemetry map (`qvault/telemetry.py`)

Every mechanism now names the telemetry that would carry its evidence: 11 sources across
Sysmon, Windows Security and System logs, PowerShell script-block logging and the TPM event
log, with the fields to inspect for each.

- Sysmon event semantics were read from the Microsoft documentation, not recalled:
  1 process create, 7 image load, 11 file create, 12/13/14 registry, 19/20/21 WMI.
- Sigma families are cited with real identifiers read from the SigmaHQ repository, and the
  module notes they are hunting content rather than a dependency.
- `rootkit_hiding` and `bootkit_boot` carry no host telemetry at all, because a host cannot
  testify about what runs before it or hides from it. Both state where the answer does come
  from instead.
- `fileless` is classified separately as execution-time only: telemetry exists (process
  ancestry, script blocks), but no autostart artefact does. An earlier version put it in the
  "no telemetry" set, and the consistency check caught the contradiction.
- EDR field names follow the Defender XDR schema so the map stays vendor-neutral.

### Verified - sources for this round

ATT&CK v20 uses Detection Strategy, Analytics and Data Components; the older "Data Sources"
vocabulary no longer applies. Bibliography entries 59-66 cover Sysmon, the 4698 event, script
block logging, the TPM 2.0 specification, the SigmaHQ repository, the Defender XDR schema,
the MSRC update guide and Mandiant's threat-intelligence blog. Entries 62-66 were added only
after the URLs resolved; a candidate measured-boot page returned 404 and was not cited.

### Added - gate G10 and generated map

`report/TELEMETRY_MAP.md` is rendered from the mapping, and G10 fails if the map is stale or
if the mapping is incomplete. 16 tests in `test_telemetry.py` (700 total).

### Added - the in-the-wild reference set (`vendor/p0_0days`, `qvault/wild.py`)

Google Project Zero's `0days-in-the-wild` is merged in as a pinned, hash-verified index:
70 root-cause analyses, 2019-2024, 28 products, at commit `e21be4bb`, Apache-2.0.

- The 18 MB of upstream markdown is not vendored; `index.json` records each RCA's CVE, year
  folder, title, product, disclosure date, upstream path, size and SHA-256, so an edited
  upstream document is visible at the next audit.
- Upstream is never read at run time. Updating means a new commit, a regenerated index and a
  reviewed diff, the same rule the vendored triage engine follows.
- The linked tracking spreadsheet reports "Last updated: 2023-04-20" and is not
  commit-pinnable, so it is not used.
- `year_is_exploitation_year()` records that `CVE-2019-17026` is filed under 2020: upstream
  files by year of exploitation, not year of CVE assignment.
- One RCA (`CVE-2021-30858`) has no heading title upstream. Recorded as an upstream gap
  rather than silently defaulted.

### Honest result - the overlap is small and that is the point

Of 70 entries, 2 mention persistence or boot artefacts and none are firmware cases.
`boundary_assessment()` states that QVault does not detect exploitation, that the layer bounds
blast radius and preserves evidence for the persistence cases, and that the remainder is out of
scope and not counted as coverage. The corpus is not used to tune any rule.

### Refused - adding Google Project Zero as a collaborator

GitHub only supports user accounts as outside collaborators. The API refused with
`"googleprojectzero is not a user"` (404). Attribution is recorded in `CONTRIBUTORS.md` and
`NOTICE` instead, which also satisfies Apache-2.0 notice retention. No invitation is pending,
and no individual at Google was invited.

### Added - gate G11

`test_wild.py` (18 tests) plus G11: the index is intact and `report/IN_THE_WILD.md` is current.
718 tests total.

### Released - merged to main

`main` moves from v0.11.0 to v0.12.0. The branch carried the policy-denial hardening, the
probe contract, the persistence detection matrix, the wire contract with gates, and the
behaviour and telemetry maps. All ten gates pass on main after the merge.

## [0.11.0] - 2026-11-02

Plane errors, the third class, and the one that makes the other two compound: an
operator acts on evidence produced by the party under investigation.

### Fixed (plane)

- **correlate** trusted a plane *label* as a source of truth. One compromised collector
  could write three labels and manufacture corroboration, which the fingerprint rule did
  not stop because fingerprints are optional. Independence now requires a named collector
  per plane; unattributed planes cannot raise a grade. Three existing tests had asserted
  the grade this used to hand out for free, and were corrected to supply attribution
  rather than weakened to keep passing.
- **lan** accepted `{"trusted": true}` as evidence that an enforcement plane is sound.
  Containment moves to an attacker-controlled plane exactly when that claim is wrong, so
  a boolean is no longer accepted: attestation requires `attested_by`, `evidence` and
  `at`, and a plane may not attest to itself. The refusal now names which of those failed.
- **verify** judged a disk it had read, and said nothing about it. Every report now
  carries `attestation: host_only` and states that a clean verdict is consistency, not
  independent evidence of integrity.

### Fixed (pilot)

- `LICENSE` contained the MIT text while `pyproject.toml` declared Apache-2.0 and the
  vendored engine is Apache-2.0. Resolved to Apache-2.0 with the full text; the
  discrepancy is recorded here rather than quietly overwritten.
- `MANIFEST.in`: an sdist now carries `report/`, `tools/` and the lock file, which
  reproduction needs and which the wheel correctly omits.

### Added

- 13 plane tests (479 total), covering unattributed planes, one collector in three
  labels, boolean and self-attestation refusal, the host-derived verdict, licence
  consistency and sdist completeness.

### Oracle sweep

No new oracle defect was found this round. The four previously closed (uniform
authentication failure, uniform store absence, constant-time key-id comparison, no
secret-derived comparison) are pinned by 9 tests, including a guard that fails the suite
if the class returns.

## [0.10.0] - 2026-11-02

Packaging is now proven rather than declared, and CI enforces it.

### Added

- `python -m build` produces a wheel containing the vendored detector (74 files,
  `vendor/zbtriage/` included), an entry point, and `qvault/lan.py`. Verified by
  installing the wheel into a clean virtualenv and running the CLI from `/tmp`, not
  from the checkout.
- GitHub Actions CI (`.github/workflows/ci.yml`, prepared and validated, not yet pushed:
  GitHub requires the `workflow` OAuth scope to create files under `.github/workflows/`,
  and the current token does not have it), four jobs: `test` (3.11 and 3.12 against `requirements-lock.txt`,
  then unit tests, smoke tests, claims ledger, fingerprint drift), `package` (wheel
  build, install, detector import, console script exercised outside the repo),
  `static` (compileall plus error-only ruff), `reproduce` (`tools/reproduce.sh`).
- `.gitignore` for bytecode, build output and virtualenvs.
- An oracle guard test: any short-circuiting comparison on a digest derived from a
  secret fails the suite, so the class of bug cannot return quietly.

### Fixed

- `rebuild_kek` compared the derived `kek_id` with `!=`. That value is derived from the
  secret KEK, and a caller can vary the reconstructed KEK freely by choosing shares, so
  the comparison leaked how many leading hex characters matched. Now `hmac.compare_digest`.

### Verified

- CI jobs simulated locally before pushing: 466 tests, 62 smoke checks, ledger valid,
  fingerprint drift clean, wheel built and installed.
- `requirements-lock.txt` installs and the gates pass in a virtualenv with no repo on
  `sys.path`.

## [0.9.0] - 2026-11-02

Two problem classes, worked line by line.

### Oracle problems (interfaces that answer questions they should not)

- `crypto` reported `authentication failed at chunk {idx}`. The index let an attacker bisect
  where their edit was detected; wrong-key and tampered-ciphertext failures also read
  differently. All authentication paths now raise one constant, `AUTH_FAILED`, carrying no
  position, no key property and no failure class.
- `store` distinguished "no envelope" from "object not found", which reveals an aborted
  ingest: ciphertext written, envelope missing. Both now answer `object <id> not available`.
- `verify` contained a `hasattr(store, "sha256_file")` fallback that silently masked a
  missing import. The import is explicit and the branch is gone.

### Pilot problems (whether a fresh checkout can be deployed and reproduced)

- No packaging existed: `pip install` was impossible and `vendor.zbtriage` would not travel.
  Added `pyproject.toml` packaging `qvault`, `vendor` and `vendor.zbtriage`, with the
  `qvault` console script.
- `requirements.txt` used `>=`, so a pilot environment could drift from the tree the numbers
  describe. Added `requirements-lock.txt` (CPython 3.11.18, cryptography 50.0.2,
  pytest 9.2.0).
- The CLI had no way to say what it was: added `qvault --version`.
- Reproduction was undocumented and unverifiable. Added `tools/reproduce.sh` and
  `report/REPRODUCE.md` with the exact expected output of every gate, verified by running
  from a clean copy of the tree rather than from git.
- `tools/gen_fingerprints.py --check` replaces the `git diff` drift check, which failed
  falsely in a checkout without `.git`.
- A missing vendor tree raised a bare ImportError; it now names the cause and the fix.

### Added

- `qvault/tests/test_oracle_resistance.py`: 8 tests asserting indistinguishability, not just
  that an error occurred. 465 tests, 62 smoke checks.

### Known limitation, not fixed

- Dual control counts approver *names*; nothing binds a name to a person, so one operator
  holding two names satisfies it. Fixing this needs an identity source the tool does not
  have, and pretending otherwise would be the failure this project documents against.

## [0.8.0] - 2026-11-02

The LAN layer existed but was unreachable: no fusion function, no CLI verb, no smoke
coverage. This release connects it to the other layers and makes it runnable.

### Added

- `lan.cross_layer()` fuses firmware attestation, endpoint findings, network deviation,
  authentication events and provenance into one graded assessment.
- `lan.load_case()` parses a case file strictly: an unknown role or malformed flow is
  refused by field name, because silently dropping hostile records under-reports.
- `qvault lan --case FILE` prints verdict, grade, identity verdict, gaps and the
  containment plan (offered steps and refused steps with alternatives).
- Smoke section 7: 8 end-to-end checks over the verb, the dedupe, the anchor gating and
  the enforcement refusals. 62 checks total.

### Fixed

- Role violation and identity assertion were graded as one claim, so a missing firmware
  anchor dragged real network evidence down to UNKNOWN and the tool under-reported.
  They are now separate: "this host violated its role" needs no anchor, "this device is
  inconsistent with its authenticated identity" does. Gaps cost one step, never erasure.
- `load_case` passed the wrong field names into `Flow` and `DiscoveryEvent`, and called
  `infrastructure_integrity` with a list where it expects the index.

## [0.7.0] - 2026-11-02

LAN layer (P8): a network is a communication environment, not a machine. Adds
`qvault/lan.py`, 30 tests and `report/LAN_LAYER.md`.

### Added
- Device identity bound to an authenticated credential; `identity_key` refuses a wireless
  label and refuses an address-only device. BSSID kept as context, never as identity.
- Per-role least-privilege service policy with out-of-role detection carrying a
  suspicion floor (lateral services grade higher than the rest).
- Traffic baseline and deviation reporting (new peer, new service, first contact), every
  entry with a benign reading.
- Discovery monitoring for mDNS, LLMNR, NetBIOS, SSDP and UPnP: an unsanctioned response
  is treated as a claim of authority over a name.
- East-west correlation graded by independent layers with flow deduplication.
- Infrastructure integrity for router, AP, switch, DNS and DHCP, including MAC-only
  identity as a weakness.
- Graded containment ladder, device-scoped by construction, refusing switch-dependent
  steps when the enforcement plane is untrusted, and refusing any step that propagates
  credentials, keys, config or binaries to other hosts.
- `identity_inconsistency()`: the cross-layer verdict, requiring a firmware anchor.

### Fixed
- `identity_inconsistency()` counted `True` inside a list of layer names, so the gate
  never fired and every case returned "insufficient". A containment gate that is
  silently always-negative is worse than no gate.

## [0.6.0] - 2026-11-02

Published-source fingerprints and their defensive inversion, for LoJax, MoonBounce and
BlackLotus.

**No sample of any family was handled.** Nothing in this repository contains malware, and no
entry is primary-sourced. Each fingerprint carries the published analysis it came from, a
benign explanation for the same artifact, the corroboration needed before it means anything,
and the control that defeats the mechanism.

### Added

- `qvault/fingerprints.py`: 11 fingerprints across three families, with `scan_text`,
  `check_image` (unnamed PE section, entry point outside sections), `check_config`
  (security-state combinations) and `defender_inversion`. A textual match is capped at
  INFERRED, and `assert_catalogue_integrity()` refuses a CONFIRMED grade, because claiming
  primary analysis of a sample that was never handled would be false.
- `tools/gen_fingerprints.py` + `report/FINGERPRINTS.md`: the document is generated from the
  code, so a fingerprint cannot exist in one and not the other.
- 20 tests, including that the rpcnetp lead carries its Absolute/Computrace false positive.

### Note

`LOJAX-1` is the honest centre of this release: the same artifact is the legitimate
anti-theft agent on a great many OEM machines. Detection without corroboration there is a
false positive by construction, which is why every entry carries `benign` and `hostile_when`.

## [0.5.0] - 2026-11-02

Adversarial testing found four defects. All four were the same failure inverted: something
unreadable, impossible or duplicated being treated as evidence.

### Fixed

- **The parser returned an empty image instead of admitting failure.** `parse_firmware`
  skipped malformed volumes silently, so garbage input produced `files=0` and looked like
  a clean read. It now records diagnostics (no `_FVH` signature, declared length beyond the
  data, invalid header length, file extending past its volume, size below its own header,
  `MAX_FILES` cap hit), counts rejected volumes, and exposes `parse_status()` and
  `parse_gaps()`. Unreadable and partial are distinct from parsed, and the gaps feed
  confidence.
- **An artifact timestamped in the future was accepted.** A future `acquired_at_ms` is a
  clock error, a fabricated envelope or a timezone mistake, and evidence that cannot be
  ordered is useless. Now refused beyond a 300s skew; zero and negative refused outright.
- **Duplicate evidence could manufacture independence.** Two copies of one record labelled
  with different plane names counted as two independent sources and raised a cluster's
  grade. Events now carry a `fingerprint`, duplicates collapse regardless of label, and a
  single fingerprint caps a cluster at INFERRED.
- **Two distinct upstreams were reported as `single_source`**, which is a false statement
  about the evidence. New `uncorroborated` standing: agreement between resellers is weak
  evidence, not corroboration. `supports_malicious_claim` stays false.

### Added

- `qvault/tests/test_adversarial.py`: 29 tests across the five attack classes — forged
  evidence, duplicated sources, malformed firmware, parser exhaustion, misleading
  timestamps. They assert refusal behaviour; a test passing because the tool said "clean"
  is treated as a bug in the test.
- `tools/smoke.py` section 6: 16 new end-to-end checks over the fixed paths, including a
  copied tree with one injected line being detected against its own published digest.
- `parse_status()` / `parse_gaps()`, `CustodyLog` unchanged, `MAX_CLOCK_SKEW_MS`.

### Changed

- Test suite 364 -> 398; smoke 38 -> 54 checks.

## [0.4.0] — 2026-11-02

Current version. The release where the tool stopped taking its own word for anything.

### Added

- **`qvault/integrity.py`** — self-integrity and impersonation detection. `build_manifest()`
  digests an installation; `verify_tree()` compares it against a digest supplied from
  outside the tree, and refuses a digest stored inside it (`SELF_EMBEDDED`) because an
  attacker who edits the module edits the recorded hash in the same change. Impersonation
  checks cover `sitecustomize.py`/`usercustomize.py` shipped inside the package, `.pth`
  execution hooks, import shadowing, world-writable code, and bytecode with no source.
- **Self-scan** — `self_scan()` runs the manifest and impersonation checks over the tool's
  own installation, so the scan covers the scanner and not only the device.
- **`combine()`** — reads a device verdict through the scanner's own status: a finding from
  an unattested instrument stands but is capped at INFERRED, and an *absence* of findings
  from one yields INCONCLUSIVE. Silence from an unverified tool is not evidence.
- **`qvault/calibration.py`** — measures false positives and false negatives instead of
  asserting them away. Confusion matrix over a labelled corpus, Wilson intervals,
  abstentions counted against accuracy, and the rule of three for a clean run (0 errors in
  40 cases is "at most 7.2%", not zero). `refuse_zero_claim()` rejects the sentence.
- **`qvault/separation.py`** — four roles (acquisition, analysis, evidence storage, trust
  verification), one per component; self-certification refused; attestation grade capped by
  evidence class; `find_circular_trust()` catches two components vouching for each other.
- **`qvault/revoke.py`** — credential revocation planning. Refresh grants and OAuth grants
  are revoked first because they mint other credentials; a request is not a revocation
  (issuer confirmation required); credentials with no revocation channel are reported as
  needing replacement rather than as revoked.
- **`qvault/budgets.py`** — resource isolation per component: wall time, memory, output
  bytes, open files, artifact size. Output is capped as well as input, and a budget kill
  produces telemetry gaps that degrade the finding rather than yielding a partial result
  presented as complete.
- **`qvault/pillars.py`** — the seven capabilities traced to a real symbol and a real test,
  generating `report/CAPABILITY_MAP.md`. A pillar holding a gap cannot be labelled
  implemented.
- **`qvault/correlate.py`** — temporal evidence graph. Grade comes from independence, not
  volume: 4 contacts in one plane stay INFERRED, while install + execution + contact across
  three planes reaches CONFIRMED. Proximity alone never raises a grade.
- **`qvault/zbt_bridge.py`** — binds the vendored detector's fourteen evidence classes to the
  local plane model, converting hits into graded observations. Detector output can never be
  a finding on its own.
- **`tools/smoke.py`** — 38 end-to-end checks over the shipped CLI surfaces.
- **`tools/check_claims.py`**, **`tools/check_findings.py`** — validators that make the
  evidence rules bind imported data, not just code paths written here.
- Report material: `report/EVIDENCE_POLICY.md`, `report/ARCHITECTURAL_LIMITATIONS.md`,
  `report/NETOBS_MODULE.md`, `report/THREAT_MODEL_REVIEW.md`,
  `report/HARDWARE_TEST_QUESTIONS.md`, `report/CLAIMS_LEDGER.csv` (53 claims, each with a
  source, a grade and a falsifier), `report/CAPABILITY_MAP.md`.

### Fixed

- Merged the repository owner's hardening commit `38235ea` (2026-11-01): boundary validation
  in stream headers and Shamir share parsing, path-traversal rejection in `retrieve`, and
  single-pass ingest. Their 5 files and 75 new tests are in this release unchanged; my
  changes sit on top and did not conflict. Total suite is 369 tests after the merge.
- `audit-signing.key` was written by `init` and then never found: every command constructed
  `AuditLog` without a `key_path`, so `checkpoint` failed with "signing key not
  initialised" on a vault that had one. The path is now derived from the log location.
- `retrieve` refuses an output directory without an `.enclave` sentinel, but nothing created
  a marked directory, so the documented workflow was unreachable. Added the `enclave` verb.
- `verify_tree()` reported a digest computed over a different tree as `MISMATCH`, i.e. as
  suspicion. A wrong reference now reports `INCOMPARABLE` and says so; a 113-file
  disagreement was never evidence of tampering.
- Process identity was `strip().lower()`, so `chrome.exe` and
  `/opt/google/chrome/chrome` never merged — the case correlation exists for. Now basename,
  case-folded, separators unified, extended-length prefix and Windows trailing dots removed.
  Stated limit: two binaries sharing a basename still merge.
- Hit counting undercounted by 2,910x on the exact incident upstream documents: 291,000
  matches on one indicator were counted as the 100 that fit in the listing. Totals now come
  from the module's counters; truncation is a telemetry gap; verdicts separate
  `serious_hits` from `listed_hits`.
- Benign truncation (a cache referencing one domain thousands of times) was pushing verdicts
  to "inconclusive", which trains readers to ignore the verdict. Only serious evidence
  truncation creates a coverage gap.
- A normal `__pycache__` was flagged as source-less bytecode because the source was sought
  beside the `.pyc` instead of in the parent directory.
- An installation absent from `sys.path` was reported as shadowed; shadowing is unanswerable
  from there, so it is now an explicit unknown.
- `calibration.evaluate()` raised `AttributeError` on a bare list. It now refuses the input
  and explains that a list of verdicts has no truth to measure against.
- Placeholder citations in the capability map named symbols and test files that do not exist;
  all seven pillars now resolve to real code.

### Changed

- **Merged with Zero-Breach-Toolkit v2.0.2** ([release](https://github.com/interplains/Zero-Breach-Toolkit/releases/tag/v2.0.2),
  commit `90148ea`), credited to **@interplains**. The library is vendored at
  `vendor/zbtriage/` (Apache-2.0, LICENSE and NOTICE preserved), byte-identical to the
  release tree and pinned by digest in `vendor/UPSTREAM.sha256` with a test enforcing it.
  Not a fork and not a rewrite: upstream owns detection, this repository owns grading.
- Version reported as `0.4.0` rather than `1.0.0`. The capability map records 0 of 7 pillars
  fully implemented and 7 partial, with every remainder named; claiming 1.0 while that is
  true would be the same overclaim the rest of this release exists to prevent.

### Known gaps

- Acquisition from a device that cannot be read (locked, encrypted, physically inaccessible).
- Indicator corpus not embedded locally: feed freshness is upstream's.
- Permission-versus-behaviour comparison not implemented.
- Hardware-backed key custody (TPM/HSM) not implemented; keys are software KEK shares.
- In-circuit versus chip-off read equivalence unverified (open question H8).
- Zone isolation and resource budgets are specified in Python and not verified to be
  enforced by the substrate. Until something outside Python enforces them, they are a
  specification rather than a control.
- No calibrated confidence from real outcomes: `calibration.py` measures, but no labelled
  corpus of real spyware samples ships here, and none will.

---

## [0.3.0] — 2026-11-01

### Added

- `qvault/firmware_integrity.py` — a separate subsystem for firmware, because an OS scan
  cannot certify the hardware hosting it. Anchor lattice from OS-mediated reads (rank 0,
  establishes nothing) to out-of-band flash reads (rank 4); host trust requires
  `flash_image` and `crtm` established by anchors that do not ask the subject.
  `certify_host()` refuses and names the missing subject.
- `qvault/findings.py` — mandatory evidence grade, at least one plausibly benign
  explanation with a disposition, telemetry gaps that lower confidence and never become a
  clean result, detection and attribution graded separately, and no `clean` value in the
  verdict type at all.
- `qvault/provenance.py` — the eight-element artifact envelope: original source,
  acquisition timestamp, SHA-256, acquisition method, tool and reader version, coverage and
  collection errors, hash-chained custody, and authenticated encryption at rest. The digest
  is computed by `capture()`, never accepted from a caller.
- `qvault/isolation.py` — zone placement with deny-by-default data flow for evidence
  readers, database parsers, indicator processing, report generation and AI-assisted
  analysis. Plaintext never flows toward the AI zone.
- `qvault/limitations.py` — the four architectural limitations as evidence planes, with
  adversarial confidence: an `on-disk` fingerprint read through the OS is not defensible
  against a capable subject.
- `qvault/netobs.py` — DNS, flow metadata, process ancestry and destination classification,
  reported as attribution divergences rather than a log of agreements.
- `qvault/netpolicy.py` — BSSID and network context as a fail-safe policy selector, with the
  rule that a BSSID may only ever lose trust and standards encoded as tests.
- `qvault/containment.py` — the six capability denials scored per enforcement plane and per
  subject posture, with claim auditing.
- `qvault/fwdiff.py` — module-level FFS/PE diff against an OEM image: added and removed
  modules, changed sections, unnamed appended sections, prologue-to-call replacement, W+X
  sections and implant immediates.
- Version 0.3.0 released.

---

## [0.2.0] — 2026-11-01

### Added

- Function-level MoonBounce reconstruction in the report, from Kaspersky's technical-details
  document: the three patched boot-service prologues, the `0x158878`-byte scan for the
  `retfq` tail of `OslArchTransferToKernel`, shellcode at physical `0x98000`, the
  relocation-directory code cave, forced W+X kernel sections, and the two name-hash
  algorithms with their constants.
- Detection signatures derived from that reconstruction, with fidelity ratings, and 14
  hardware-test questions no document can answer.

### Fixed

- The report previously marked the hooked loader and kernel functions `UNKNOWN`; that claim
  was retracted once the primary source was obtained.

---

## [0.1.0] — 2026-11-01

### Added

- Initial vault: AES-256-GCM streaming encryption, Shamir KEK shares, write-once object
  storage, hash-chained audit log with Ed25519 checkpoints, dual-control retrieval gated on
  the `.enclave` sentinel, and `verify`.
- `report/UEFI_Malware_Deep_Dive_Report.md` — LoJax, MoonBounce and BlackLotus with per-claim
  evidence grades, plus the cryptographic quarantine design and its failure analysis.

# Changelog

All notable changes to qvault. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Evidence grades appear throughout: **CONFIRMED**, **CORROBORATED**, **INFERRED**,
**HYPOTHESIS**, **UNKNOWN**. See `report/EVIDENCE_POLICY.md` for what they mean and what
they deliberately do not mean.

---

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

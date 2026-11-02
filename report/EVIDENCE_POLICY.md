# Evidence policy, and a self-audit of this project

This document exists because the report's evidence tags, as originally published,
were ambiguous in a way that mattered. It states the rules this project is held
to, redefines the tags precisely, records where the author broke his own rules,
and lists what would falsify the report.

---

## 1. The three rules

**R1. No claim of reverse engineering where only vendor reports were read.**
Reading a technical publication is *secondary-source reconstruction*. It is
legitimate and useful. It is not reverse engineering, and it must never be
described as such.

**R2. No implementation before the threat model has survived independent
criticism.** An architecture that has only been criticised by its author has not
been criticised.

**R3. Every technical conclusion carries evidence, a confidence classification,
and reasoning another person can reproduce.**

---

## 2. What the tags mean (revised)

The original §0.2 table defined the tags but did not say *whose* verification
they describe. Corrected semantics:

| Tag              | Means, precisely                                                                                                                                                                               |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CONFIRMED**    | A primary source *directly demonstrates* the claim with technical evidence (decompilation, byte structure, named artifact, vendor specification). **It does not mean the author verified it.** |
| **CORROBORATED** | Two or more *independent* sources agree, at least one of them technical.                                                                                                                       |
| **INFERRED**     | A conclusion drawn by the author from confirmed material, via reasoning stated in the text. Not observed.                                                                                      |
| **HYPOTHESIS**   | Plausible and consistent, unproven. Stated so it can be attacked.                                                                                                                              |
| **UNKNOWN**      | Insufficient public evidence. Not guessed.                                                                                                                                                     |

And a second, orthogonal dimension that the first release lacked:

| Verification status | Means                                                                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| **none**            | Taken from a published source. Nobody in this project re-derived it. This covers every claim about LoJax, MoonBounce and BlackLotus. |
| **partial**         | Derived here from published artifacts (e.g. signature sets, diff logic) but not validated against a real sample.                     |
| **independent**     | Produced and checked inside this repository, with an executable test. Only used for `qvault`'s own behaviour.                        |

**Standing statement:** this project performed no independent reverse
engineering. No sample was obtained, unpacked, disassembled, emulated or
executed. Any sentence implying otherwise is a defect to be corrected, not
interpreted generously.

---

**R4. Every finding carries an evidence grade.** No finding exists as prose.

**R5. Every finding considers at least one plausible benign explanation.** Including
the finding that says "this is fine", which is why the rule applies to all-clear
results too.

**R6. Missing telemetry lowers confidence; it never silently becomes a clean
result.** A surface that was not examined declares itself, and reduces the grade.

**R7. Detection and attribution are separate.** You may not be more certain who did
something than that something happened, and the two are graded independently.

**R8. The tool never calls a device clean because no known spyware was found.**
`clean` is not a value the verdict type can produce.

R4-R8 are enforced in `qvault/findings.py` rather than reviewed by hand: `Finding`
refuses to construct, confidence is computed rather than asserted, attribution is
capped by detection, and `DeviceAssessment.verdict` has no branch that returns
cleanliness. `tools/check_findings.py` applies the same checks to findings imported
from other tools.

**R9. Every collected artifact carries an eight-element envelope.** Original source,
acquisition timestamp, SHA-256, acquisition method, tool and reader versions,
coverage and collection errors, chain of custody, and cryptographic protection at
rest. Enforced in `qvault/provenance.py`: the envelope will not construct without
them, the digest is computed from the bytes rather than supplied, custody is
hash-chained from the acquisition event, and unauthenticated ciphers are refused.

Two of these deserve explanation because they are routinely fudged:

*Coverage* is not a courtesy field. A read that covered 60% of the flash produces
telemetry gaps automatically, which lower the confidence of anything resting on it
(rule F3). Nobody has to remember to mention it.

*Tool version and reader version are separate* because they fail differently. A
capture bug means the bytes are wrong; a reader bug means the bytes are right and
the interpretation is wrong. One needs re-acquisition, the other re-parsing, and the
envelope has to be able to tell them apart.

## 3. Self-audit: where this work broke its own rules

Recorded rather than quietly fixed, because a report that hides its process is
not evidence.

### 3.1 Rule 1 violations

| Where                  | Problem                                                        | Correction applied                                                                                                                                              |
| ---------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Title and §0.1         | "A Reverse-Engineering Study" reads as first-hand analysis     | Title retained (the study *of* reverse-engineering literature) but §0.5 now states the limitation explicitly and every family section header carries the source |
| §0.2 (original)        | Tags appeared to record the author's verification              | Redefined in §2 above with an explicit second dimension                                                                                                         |
| §3.8 heading           | "Function-level reconstruction" could imply independent RE     | Corrected to attribute the reconstruction to Kaspersky's document in the first line                                                                             |
| Chat / commit messages | "the mechanism is now fully reconstructable"                   | True of the *documented* mechanism only; overstated as a general claim                                                                                          |
| §3.9                   | Signature table presented without a verification-status column | §3.9 now states that no signature has been validated against a live sample                                                                                      |

### 3.2 Rule 2 violations

| Where                   | Problem                                                                                                                            |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Whole `qvault/` package | Written *before* §11 (failure analysis) existed. The mitigations were retrofitted to existing code rather than driving its design. |
| §11                     | Self-authored criticism only. No independent reviewer.                                                                             |
| §12 roadmap             | Presented phases as if the design were settled, with no review gate                                                                |
| README                  | Presented the architecture as "reference implementation" without noting unreviewed status                                          |

**Correction:** `qvault` is now labelled **prototype, not hardened** in the README
and in §13, `report/THREAT_MODEL_REVIEW.md` exists as the artifact an independent
critic needs, and §12 contains an explicit gate before Phase 1 hardening.

### 3.3 Rule 3 gaps found on re-reading

1. **CORROBORATED was over-applied.** Several claims tagged CORROBORATED rest on
   a single technical source plus author inference. The ledger below reclassifies
   them as CONFIRMED (single source) or INFERRED, as appropriate.
2. **Falsifiers were absent.** No claim stated what evidence would refute it, so
   none could be attacked. `CLAIMS_LEDGER.csv` now requires a falsifier per row,
   enforced by `tools/check_claims.py`.
3. **Section references were not machine-checkable.** The validator confirms that
   every claim points at a section that actually exists in the report.
4. **Timeline inference was presented with component facts.** §3.8's 2018 build
   dates are CONFIRMED; the conclusion "built late 2018, deployed after" is
   INFERRED and is now a separate ledger row.

---

## 4. What would falsify this report

Stated so a critic has targets rather than impressions.

| Claim                                                           | Falsified by                                                                      |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| LoJax survives a full-region firmware update                    | A hardware test showing survival after a complete BIOS-region rewrite             |
| A partial firmware update cannot remove an implanted FFS file   | A vendor capsule that preserves free space yet removes a foreign file             |
| Secure Boot does not attest firmware volume contents            | A platform whose Secure Boot verification demonstrably covers its own DXE volumes |
| MoonBounce leaves no structural firmware fingerprint            | A structural (non-byte-diff) detector that reliably finds an in-place DXE patch   |
| `0x6F4EB841` is unique to this implant                          | Any legitimate firmware component containing that immediate                       |
| Encryption at ingestion prevents execution of the stored object | Any path that executes a sealed object without a retrieval authorisation          |
| The audit chain detects truncation                              | A log rewrite that passes `verify` including checkpoint comparison                |
| BlackLotus is fully removed by OS + ESP reformat                | Survival of the bootkit after a reformat with ESP wipe and MOK revocation         |

---

## 5. Reproduction instructions

```bash
pip install -r requirements.txt
python -m pytest qvault/tests -q          # 30 tests, all vault/fwdiff behaviour
python tools/check_claims.py              # validates the claims ledger
```

`check_claims.py` fails if any claim lacks a source, a valid tag, a falsifier, or
points at a section that does not exist. Any claim about the three malware
families must carry `verification=none`; only claims about this repository's own
code may be `independent`.

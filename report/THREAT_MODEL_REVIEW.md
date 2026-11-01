# Threat model: review status and the case against this design

**Status: the gate is OPEN. This design has not survived independent criticism.**

This document exists so that an independent reviewer has targets instead of
impressions, and so nobody mistakes a self-authored failure analysis for review.
Rule R2 of this project says implementation does not proceed until the threat
model has been attacked by someone who did not write it. The code in `qvault/`
was written before that rule was applied, so it is labelled **prototype, not
hardened** in the README and in §13 of the main report.

---

## 1. What must be reviewed

| Boundary | The claim under review |
|---|---|
| B1 Subject → appliance | Bytes can be captured out of band without the subject influencing the capture |
| B2 Appliance → vault | Ciphertext and metadata can be produced by a semi-trusted host and still be trustworthy later |
| B3 Vault → control plane | Key material stays out of the storage host, and disclosure requires a quorum |
| B4 Control plane → enclave | Authorisation for a specific object, by specific people, for a specific purpose, is enforceable |
| B5 Enclave → outside world | Plaintext cannot leave except as authorised, reviewable results |

## 2. Assets

A1 preserved sample bytes · A2 custody record and audit history · A3 the
organisation's production network · A4 the enclave's integrity · A5 key material ·
A6 the analytical conclusions drawn from the evidence.

An important ordering point: **A1 is not the most valuable asset.** For a
containment system, A3 and A4 outrank it. A vault that leaks one sample into
production has failed worse than one that loses a sample.

## 3. Adversaries

| ID | Adversary | Capability assumed |
|---|---|---|
| T1 | The sample itself | Executes at boot on the subject; may be a firmware implant; may exploit any parser it reaches |
| T2 | Operator error | Authorised, well-intentioned, in a hurry; opens the wrong file, "just checks something" on a workstation |
| T3 | Single insider | Authorised access to one zone; wants to exfiltrate a sample or destroy evidence |
| T4 | Compromised ingestion host | Root on the appliance before or during ingestion |
| T5 | Compromised vault administrator | Root on the storage host; can read and rewrite everything except keys and external anchors |
| T6 | Supply chain | Controls a dependency, build or release of the vault software |
| T7 | Physical attacker | Access to hardware; DMA-capable port; can steal drives |

## 4. The design's falsifiable claims

Each claim is stated so an attacker has a specific thing to break. If any one of
these falls, the corresponding boundary is decorative.

| ID | Claim | Broken by |
|---|---|---|
| C1 | A sealed object cannot be executed without a retrieval authorisation | Any path that produces plaintext without quorum + dual control |
| C2 | A modified stored object is always detected | A byte change that passes `verify` *and* decrypts |
| C3 | A rewritten audit history is always detected | Rewriting the log and re-signing it, undetectably, with anchors intact |
| C4 | Losing K-1 shares reveals nothing about the KEK | Distinguishing K-1 shares from random bytes, or a share-combination oracle |
| C5 | Compromise of the vault host does not disclose samples | Reading plaintext from the storage host |
| C6 | Approvals are attributable to distinct real people | Self-approval under a second name, without leaving evidence |
| C7 | Retrieval targets only an enclave | Writing plaintext outside a marked enclave |
| C8 | Ingestion cannot silently substitute the object | Landing a different object without the audit or verify noticing |
| C9 | Truncation of the log is detected | Removing trailing entries and passing verification |
| C10 | The enclave cannot leak plaintext except as authorised results | Any covert path out (network, DMA, side channel, human) |

## 5. Self-critique: nine weaknesses found on re-reading the code

These are the author's own findings. They are recorded as findings, not as
fixed issues. Severity is the author's judgement and is itself reviewable.

| # | Weakness | Severity | Why it matters | Cheapest credible fix |
|---|---|---|---|---|
| W1 | Approval files are plain JSON written by the vault process, and "requester ≠ approver" is a **name comparison** | **High** | Anyone who can run the CLI can approve as `reviewer2`. Dual control is then theatre, and C6 falls immediately. | Custodian-signed approval tokens (Ed25519, keys held off-host), verified by the vault; identity from SSO, not `--approver` |
| W2 | The audit signing key lives at `<vault>/audit-signing.key`, inside the same trust domain as the log | **High** | An attacker with write access rewrites history and re-signs it. C3 and C9 fall together. | Key in HSM or offline; or sign with custodian smartcards at checkpoint time |
| W3 | Whole-vault rollback is undetected | **High** | Restoring an older snapshot yields a chain that verifies. Deleted objects simply never existed. | External anchor with a monotonic counter; verify must compare against an anchor it cannot edit, not the newest checkpoint file *inside* the vault |
| W4 | `verify` reads the newest checkpoint from the vault itself | **High** | An attacker deletes checkpoints and truncates; nothing compares against an outside value | Checkpoints replicated to the control plane; verify refuses to pass without an external head |
| W5 | The `.enclave` sentinel is forgeable: `touch .enclave` defeats it | Medium | It is a speed bump against T2, not a control against T3/T5 | Mount-option enforcement (`noexec`, separate filesystem), policy check against an allow-list of enclave hosts, not a marker file |
| W6 | Retrieval writes plaintext to a **file**, not a pipe or memory | Medium | Plaintext persists inside the enclave; root there reads it, and a snapshot captures it | Decrypt to a pipe consumed by the analysis tool, or to a tmpfs with `noexec,nosuid` and explicit teardown |
| W7 | `0400` permissions are asserted as immutability | Medium | Mode bits stop accidental writes, not root. The README says this; the code's `verify` only *warns* on writable objects | Fail `verify` on a writable object in strict mode; rely on WORM storage for the real property |
| W8 | No concurrency control on approvals or retrieval (TOCTOU) | Low | Two simultaneous retrievals can both pass a check that was true once; the audit shows both, but the second may reuse a stale state | Per-object advisory lock with the lock itself audited |
| W9 | No size or rate limits on ingest | Low | A trivial denial of service against the vault, or of the appliance's disk | Hard cap per object and per day, enforced before the first byte is encrypted |

Two more that are not code defects but design assumptions a reviewer should
attack: the appliance is assumed to be re-imaged per case (unverified), and the
enclave is assumed to be physically isolated (unverified, and it is where
plaintext lives).

## 6. Reviewer checklist

Answering "no" to any of these is a finding.

**Boundary B2 (appliance → vault)**
1. What stops the appliance from writing a different object than it reports?
2. Where does the expected hash originate, and is that device independent?
3. Can the appliance reach the enclave, the control plane, or the internet?
4. What is the evidence that the appliance image was clean at capture time?

**Boundary B3 (vault → control plane)**
5. Where does the KEK exist in plaintext, and for how long?
6. Who can modify the verification policy, and is that change audited elsewhere?
7. Is the audit head verifiable without trusting any host in this design?
8. What happens to all objects if one custodian is unavailable for a month?
9. What happens if a custodian leaves, and is that rehearsed?

**Boundary B4 (control plane → enclave)**
10. How is an approval bound to a specific object and purpose?
11. Can one person produce two identities that both approve?
12. Is there a break-glass path, and what is logged when it is used?
13. Can an approval be replayed for a later retrieval?

**Boundary B5 (enclave → outside)**
14. Enumerate every byte path out of the enclave.
15. Can the enclave host's own firmware be trusted, and how would you know?
16. What reverts the enclave between cases, and is it verified?
17. Can memory from case N be read during case N+1?

**Adversary-specific**
18. T1: which parsers does the sample reach, and what happens when one crashes?
19. T2: what is the easiest accidental-execution path, honestly?
20. T3: what can one insider do alone, with only their own credentials?
21. T4: which of the vault's guarantees survive a lying appliance? (Answer: none about provenance; state it.)
22. T5: same question for the vault host. (Answer: confidentiality and anchored history, if W1-W4 are fixed.)
23. T6: how is a release verified, and by whom?
24. T7: what does an attacker with 30 minutes and a screwdriver get?

## 7. Exit criteria for the gate

The gate opens when all of the following are true, and not before:

1. An independent reviewer has worked through §6 and every answer is recorded.
2. Every **High** finding from review is either fixed with a test, or accepted in
   writing with a named owner and a residual-risk statement.
3. W1-W4 are resolved, because each of them individually reduces "dual control"
   or "tamper-evident audit" to a claim rather than a property.
4. The adversarial tests derived from the review exist in `qvault/tests/` and
   fail against the current implementation, or pass against the fixed one.
5. The residual-risk table in report §11 is updated with review findings, not
   author findings.

Until then: prototype. Used on synthetic fixtures only.

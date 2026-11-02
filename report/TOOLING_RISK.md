# Tooling risk: the tool as an attack surface

Release **0.13.11**. This project parses hostile firmware for a living, which
makes it part of the reader's problem rather than only part of the answer. This
register lists every component that consumes input it does not control, the guard
found by reading that component, and the gap that remains.

> **Read the `none observed` rows as written.** They mean no bound was found in the
> module, not that the module is safe. This page is a risk register, not a
> certification, and nothing on it grades above `CORROBORATED`.

## Where the register stands

- No component has been fuzzed. There is no harness in `tools/` and no corpus in the tree. *(CONFIRMED)*
- Python removes the memory-safety class (buffer overflows, use-after-free) that a C parser of the same inputs would carry. It does not remove unbounded allocation, quadratic scanning, or logic errors in length handling. *(CORROBORATED)*
- Handling hostile input without executing it is the design and is visible in the code; that it is robust against a determined adversary is not established, and no claim here says so. *(CONFIRMED)*

## Components that parse input they do not control

| Module                   | Consumes                                                       | Guard found                                                                                       | Remaining gap                                                                                                                                                           |
| ------------------------ | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `qvault/fingerprints.py` | firmware bytes and indicator text                              | text-derived grade capped at INFERRED (`MAX_TEXT_GRADE`)                                          | Matching is linear per indicator; an indicator set large enough to be quadratic on a hostile image is not bounded or measured.                                          |
| `qvault/fwdiff.py`       | two firmware images, arbitrary bytes                           | explicit caps: MAX_FILES 4096, MAX_SECTIONS 96, MAX_PE_CANDIDATES 4                               | Caps bound the count of structures, not the cost of comparing two near-identical large images inside those caps.                                                        |
| `qvault/ingest.py`       | evidence blobs from an operator or an acquisition              | none observed: hashing and metadata capture; bounds come from the caller                          | No independent size ceiling here, so a caller that streams an unbounded blob is trusted not to. That is an assumption, not a check.                                     |
| `qvault/store.py`        | on-disk store files, writable by anyone who reaches the volume | refuses a second open for writing; unrecognised enum values refused, not defaulted                | The store trusts file permissions (seal 0400) plus the audit chain. A writer with the volume mounted can replace a file; detection is the chain's job, not the store's. |
| `qvault/audit.py`        | audit log entries, attacker-writable between runs              | hash chain plus checkpoint verification, so deletion mid-chain fails verification                 | Truncation at the head is detected only against a checkpoint held elsewhere; if both are replaced, the shorter chain verifies as valid.                                 |
| `qvault/provenance.py`   | manifests and vendored-source trees                            | `hmac.compare_digest` for secret-derived comparisons                                              | A modified vendored tree is caught only if its pinned hash is checked, and the pin is data in the same repository it is meant to protect.                               |
| `qvault/retrieve.py`     | object identifiers from a caller                               | `hmac.compare_digest` on identifier comparison                                                    | Comparison is constant-time; the surrounding lookup is not, so the guarantee is about one comparison, not about the operation.                                          |
| `qvault/keys.py`         | key material and identifiers                                   | none observed at this layer beyond storage; comparisons are delegated                             | Key lifetime and zeroisation are not enforced by the language. Python strings are immutable, so a key in memory is presumed present until the process exits.            |
| `qvault/crypto.py`       | sealed ciphertext, which an attacker may control               | AES-256-GCM: authentication is checked before plaintext is used                                   | No adversarial test of chunk framing or truncation; the framing assumptions are covered by unit tests written from the same model as the implementation.                |
| `qvault/triage.py`       | bytes from the vendored zbtriage engine                        | vendored at a pinned revision; high-frequency indicator counting fixed after an undercount defect | Third-party code is trusted at its pin. Its upstream changes are audited by hand, and that audit is not automated.                                                      |
| `qvault/wild.py`         | the in-the-wild dataset (pinned snapshot)                      | pinned snapshot; entries are metadata, not samples                                                | Parsed as trusted because it is vendored. If the snapshot is regenerated, nothing re-validates its schema.                                                              |
| `qvault/netobs.py`       | LAN telemetry: device records, flow metadata, discovery output | BSSID treated as context, never as a key or identity                                              | Records are supplied by an agent on a network the adversary may control, so identity claims are corroborated at best.                                                   |

12 registered components. A test fails if a module takes `bytes` or parses JSON and is missing from this table, so the register stays complete as the code grows.

## What a reader should do with it

Run this on a machine you can rebuild. Treat the evidence store as data written by an adversary, because a bootkit that knows it is being collected will try to write it. Neither of those is a paranoid reading of the code; both follow from the rows above.

## What this page does not claim

It does not claim the parsers are safe, bounded, or audited by anyone other than this project. It claims that each component consuming untrusted input is named, that its guard is described at the level it was verified, and that its gap is written down rather than left for a reader to discover during an incident.

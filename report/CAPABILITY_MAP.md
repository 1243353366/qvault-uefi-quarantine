# Capability map — seven pillars, traced to code

0 of 7 capabilities fully implemented, 7 partial, 0 with a required gap. Partial means the stated subset works and the rest is named.

| Pillar | Status | Implemented | Gaps named |
|---|---|---|---|
| P1 Forensic acquisition — device artifacts, provenance, coverage | PARTIAL | 3/4 | acquisition from a device that cannot be read without the OS |
| P2 IOC detection — retain known spyware detection | PARTIAL | 2/3 | indicator corpus embedded locally |
| P3 Behavioral correlation — processes, permissions, network, persistence | PARTIAL | 2/4 | process identity normalisation across hosts, permission-versus-behaviour comparison |
| P4 Cryptographic evidence vault — authenticated encryption, immutable originals, audit | PARTIAL | 3/4 | hardware-backed key custody (TPM/HSM) |
| P5 Firmware integrity — independent boot-chain and firmware verification | PARTIAL | 2/3 | in-circuit versus chip-off read equivalence |
| P6 Containment — quarantine, resource isolation, credential revocation | PARTIAL | 3/4 | zone isolation enforced by the substrate |
| P7 Evidence assessment — confidence, alternatives, explicit unknowns | PARTIAL | 3/4 | calibrated confidence from real outcomes |

## Unfinished work, in one place

`gap_register()` returns this list; it is reproduced here so nothing depends on
someone remembering a conversation.

| Pillar | Requirement | Status | Required | Why not |
|---|---|---|---|---|
| P1 | acquisition from a device that cannot be read without the OS | PARTIAL | no | reported as unattested rather than acquired; needs physical access |
| P2 | indicator corpus embedded locally | GAP | no | deliberate: an embedded feed reproduces the staleness problem in A4 |
| P3 | process identity normalisation across hosts | PARTIAL | yes | subject is a lower-cased string; path and signature identity are not resolved, so two spellings of one binary do not merge |
| P3 | permission-versus-behaviour comparison | PARTIAL | no | permission events correlate but no entitlement model is consulted |
| P4 | hardware-backed key custody (TPM/HSM) | GAP | no | keys are software-held shares; no HSM or TPM seal is implemented |
| P5 | in-circuit versus chip-off read equivalence | PARTIAL | no | penalised rather than measured; H8 is open |
| P6 | zone isolation enforced by the substrate | PARTIAL | yes | the model states the boundary; nothing verifies a hypervisor honours it |
| P7 | calibrated confidence from real outcomes | GAP | no | grades are principled but not yet checked against known-truth cases |

## Two requirements are load-bearing and partial

**P3 process identity normalisation** is required and partial: subjects are
lower-cased strings, so two spellings of one binary do not merge. Correlating
behaviour across a filesystem that can rename things is not solved by string
matching, and a correlation engine that silently misses merges is worse than
one that reports its blind spot.

**P6 substrate enforcement** is required and partial: `isolation.py` and
`budgets.py` state the boundary and the ceiling; nothing verifies that the
hypervisor or container runtime honours either. The model is a specification
until something outside Python enforces it.

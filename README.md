# qvault

[![ci](https://github.com/1243353366/qvault-uefi-quarantine/actions/workflows/ci.yml/badge.svg)](https://github.com/1243353366/qvault-uefi-quarantine/actions/workflows/ci.yml)

CI runs the suite this README describes: tests on 3.11 and 3.12, all sixteen gates, docs drift, both link checks, a wheel install outside the checkout, and static analysis, every step under `set -o pipefail`. Locally, `.githooks/pre-push` runs the same gates and blocks a push that fails one: `bash tools/install_hooks.sh`.

**Version 0.13.5** · [documentation site](https://1243353366.github.io/qvault-uefi-quarantine/) · [CHANGELOG](CHANGELOG.md) · [citations](CITATIONS.md) · [capability map](report/CAPABILITY_MAP.md) — a cryptographic quarantine vault for firmware evidence

> **Status: prototype, not hardened.** The code was written before the threat model
> had been independently reviewed, which is the wrong order. Nine weaknesses found
> on re-reading are listed in
> [`report/THREAT_MODEL_REVIEW.md`](report/THREAT_MODEL_REVIEW.md); the four rated
> High each reduce dual control or tamper-evident audit from a property to a claim.
> Use it on synthetic fixtures, not on live samples.

Reference implementation of the defensive architecture described in
[`report/UEFI_Malware_Deep_Dive_Report.md`](report/UEFI_Malware_Deep_Dive_Report.md).

The goal is narrow and deliberately unglamorous: **preserve hostile firmware as
evidence, while denying it any opportunity to execute.** This is a custody and
containment tool. It is not an analyser, not a sandbox, and not a cleaner. It
does not repair infected hardware.

```
ingest ──► hash ──► AES-256-GCM (chunked) ──► seal 0400 ──► audit chain
                │                                          │
                └──── DEK wrapped by Shamir-split KEK ──────┘

retrieve ──► K-of-N shares ──► 2-person approval ──► enclave sentinel ──► 0400 plaintext
```

## Documentation

The full documentation is published at
**<https://1243353366.github.io/qvault-uefi-quarantine/>**, generated from this repository by
`tools/build_docs.py`, so the site cannot claim more than the code does.

| Page                                                                                                                                                            | What it answers                                                                          |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [Deep dive](https://1243353366.github.io/qvault-uefi-quarantine/deep-dive)                                                                                      | LoJax, MoonBounce and BlackLotus, with the architecture and the bibliography             |
| [Zero-days in the wild](https://1243353366.github.io/qvault-uefi-quarantine/in-the-wild)                                                                        | The pinned Project Zero reference set, and why the overlap with this boundary is 2 of 70 |
| [Behaviour to control](https://1243353366.github.io/qvault-uefi-quarantine/threat-behavior-matrix)                                                              | 17 attacker behaviours, the control that answers each, and the gaps named                |
| [Telemetry map](https://1243353366.github.io/qvault-uefi-quarantine/telemetry-map)                                                                              | What feeds each detection: Sysmon, Windows events, script blocks, TPM log                |
| [Persistence](https://1243353366.github.io/qvault-uefi-quarantine/persistence)                                                                                  | Fourteen autostart mechanisms and four result classes                                    |
| [Acquisition and analysis](https://1243353366.github.io/qvault-uefi-quarantine/acquisition)                                                                     | Dump-based workflow, tooling, air-gap, and what an emulator cannot tell you              |
| [Trust model](https://1243353366.github.io/qvault-uefi-quarantine/trust-model) · [Limitations](https://1243353366.github.io/qvault-uefi-quarantine/limitations) | What is programmatically enforced, and what is deployment-dependent                      |
| [Citations](https://1243353366.github.io/qvault-uefi-quarantine/citations)                                                                                      | All 68 sources, each with where it is used                                               |

Every claim in the reports carries a source, a tag, a status and a falsifier in
`report/CLAIMS_LEDGER.csv`; gate G3 fails if a claim has no source and gate G12 fails if the
published site is stale.

## Read this before trusting any claim in here

This project performed **no independent reverse engineering**. No sample was
obtained, unpacked or executed. Every statement about LoJax, MoonBounce and
BlackLotus is a reconstruction from published vendor analysis, and every
signature in `qvault/fwdiff.py` is derived from documented bytes without live
validation.

- [`report/EVIDENCE_POLICY.md`](report/EVIDENCE_POLICY.md) — the three rules this
- [`report/DENIAL_MODEL.md`](report/DENIAL_MODEL.md) — the three ways to deny an attacker
  (access, capability, execution), each with its non-claims and the condition under
  which the denial ends; no denial claim reaches CONFIRMED
  project is held to, revised tag semantics, and a self-audit of where it broke them.
- [`report/CLAIMS_LEDGER.csv`](report/CLAIMS_LEDGER.csv) — 48 claims with source,
  locator, tag, verification status and a falsifier.
- [`report/HARDWARE_TEST_QUESTIONS.md`](report/HARDWARE_TEST_QUESTIONS.md) — the 14
  questions no document can answer, with rigs and experiments.
- [`report/THREAT_MODEL_REVIEW.md`](report/THREAT_MODEL_REVIEW.md) — what a critic
  should attack, and why the review gate is still open.

```bash
python tools/check_claims.py     # fails on any claim missing evidence or falsifier
```

## Why each piece exists

| Mechanism                                    | Threat it addresses                                                             | Why not something simpler                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Encrypt at ingestion, streaming              | Accidental execution, casual inspection, backup/AV crawlers touching the sample | A password-protected zip still writes a plaintext temp file during `zip`      |
| Fresh DEK per object                         | One leaked key burns one sample, not the vault                                  | A single vault key means any single compromise is total                       |
| KEK split K-of-N (Shamir, GF(256))           | Compromise of the vault host or any one custodian                               | A KEK in one file is one credential away from full disclosure                 |
| Dual-control approvals, requester ≠ approver | Insider misuse, rushed "just decrypt it"                                        | Logging alone does not prevent, only records                                  |
| Enclave sentinel directory                   | Decrypting straight into a workstation or production share                      | Path checks alone are bypassable by symlink or mount games                    |
| Chunked AEAD with metadata binding           | Silent corruption, sample swapping, truncation                                  | A plain SHA-256 manifest cannot tell you *which* bytes changed or stop a swap |
| Content-address by ciphertext hash           | Plaintext hash as a confirmation oracle                                         | Content-addressing by plaintext hash leaks "do you have sample X?"            |
| Hash-chained audit + signed checkpoints      | Log editing, entry deletion, history rewrite                                    | A normal log file is editable by anyone with write access                     |
| Inert triage (bounded reads only)            | Parser exploitation at the boundary                                             | Deep FFS/PE parsing at ingestion turns the vault into an attack surface       |

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest qvault/tests -q      # 418 tests, ~0.75s
```

Requires Python 3.10+ and `cryptography`.

## Use

```bash
# 1. Create the vault. It prints three share files: give them to three people.
python -m qvault init --root vault --shares 3 --threshold 2 --custodian-dir custodian

# 2. Ingest. Password-free, non-interactive, suitable for an acquisition appliance.
python -m qvault ingest --root vault --file dump.bin \
    --operator aadi --method "SPI flash dump (CHIPSEC)" \
    --share custodian/share-1.json --share custodian/share-3.json

# 3. Two different people approve a specific retrieval.
python -m qvault approve --root vault --id <object-id> --approver reviewer1 --justification "case 2026-11"
python -m qvault approve --root vault --id <object-id> --approver reviewer2 --justification "case 2026-11"

# 4. Retrieve into an analysis enclave (a directory containing a .enclave marker).
mkdir -p enclave && touch enclave/.enclave
python -m qvault retrieve --root vault --id <object-id> --requester analyst \
    --out enclave --share custodian/share-1.json --share custodian/share-2.json

# 5. Integrity and custody checks.
python -m qvault verify --root vault
python -m qvault audit --root vault
python -m qvault checkpoint --root vault     # sign the current audit head
```

## Network observation

`qvault/netobs.py` records DNS, flow metadata, process ancestry and destination
classification, then does the part that matters: joins what the host **claims**
against what the wire **shows**.

```bash
python -m qvault netobs --input case.json     # {host:[], wire:[], dns:[]}
```

The output leads with disagreements (`unattributed_egress`, `phantom_claim`,
`attribution_conflict`) because agreement is not evidence of innocence. On a host
running BlackLotus or MoonBounce, endpoint attribution names `winlogon.exe` or
`svchost.exe` exactly as designed, so the named-process rules see legitimate
components doing legitimate-looking things. Only the divergence rule notices.

Metadata only: no payloads, no query strings, no third-party traffic. Design,
privacy constraints and ten failure modes: `report/NETOBS_MODULE.md`.

> **Built on [Zero-Breach-Toolkit](https://github.com/interplains/Zero-Breach-Toolkit) by
> [@interplains](https://github.com/interplains)** — release **v2.0.2**
> (`90148ea`, Apache-2.0), vendored unmodified at `vendor/zbtriage` and pinned by digest
> in `vendor/UPSTREAM.sha256`. The detector is theirs; the grading, correlation,
> containment and verification around it are what this repository adds. See
> `CREDITS.md`.

## The scan covers the scanner

`qvault/integrity.py` scans this installation as an artifact: file digests, interpreter
startup hooks inside the package, import shadowing, world-writable code, `.pth` hooks,
bytecode with no source. It refuses a digest stored beside the code it describes, and a
self-computed digest with no external reference is `unverified`, never verified.

A device result is then read through the scanner's own status: a finding from an
unattested instrument stands but is capped at INFERRED, and an absence of findings from
one is INCONCLUSIVE.

`qvault/calibration.py` measures false positives and false negatives against a labelled
corpus with Wilson intervals. Abstentions count against accuracy, and zero-error claims
are rejected by `refuse_zero_claim()`: zero errors in n cases is a bound of about 3/n,
not an absence.

## The engine cannot certify itself

Four roles, one per component: acquisition, analysis, evidence storage, trust
verification. `qvault/separation.py` refuses an attestation when the attestor is the
subject, when both hold the same role, or when the evidence is the subject's own report
relayed by an intermediary. Only the verification role may attest. Grade is capped by
evidence class, and mutual peer attestation is detected as a trust cycle.

The regress is named, not hidden: every attestation records its root, and with no root
the result is `unverified` with an `unverified_root` gap.

## Seven capabilities, traced to code

`report/CAPABILITY_MAP.md` is generated from `qvault/pillars.py`, which names the module
and test for every requirement and refuses to label a pillar implemented while a
required piece is missing:

| Pillar                          | Status        |
| ------------------------------- | ------------- |
| P1 Forensic acquisition         | partial (3/4) |
| P2 IOC detection                | partial (2/3) |
| P3 Behavioral correlation       | partial (2/4) |
| P4 Cryptographic evidence vault | partial (3/4) |
| P5 Firmware integrity           | partial (2/3) |
| P6 Containment                  | partial (3/4) |
| P7 Evidence assessment          | partial (3/4) |

Two requirements are load-bearing and partial: P3 process identity normalisation
(subjects are strings, so two spellings of one binary do not merge) and P6 substrate
enforcement (`isolation.py` and `budgets.py` state the boundary; nothing verifies the
hypervisor honours it).

## Merged with Zero-Breach-Toolkit

The upstream detector is vendored unmodified at `vendor/zbtriage` (Apache-2.0, pinned
commit in `vendor/UPSTREAM.md`). The split is by responsibility: upstream decides which
artifacts to read and which indicator matched; qvault decides what that match is worth.

- `qvault/zbt_bridge.py` maps each upstream `EV_*` class to an evidence plane and grade,
  fails loudly if upstream adds a grade nobody mapped, converts hits to `Observation`s
  (never `Finding`s), and refuses family attribution on a single feed.
- `qvault/correlate.py` is the temporal evidence graph: grade comes from independence,
  not from event count. Four contacts from one plane stay `INFERRED`.
- Honest consequence: every upstream grade lands on the historical plane, which is
  forgeable by the subject, so `adversarial_value()` returns `none` even for an
  `on-disk` fingerprint.

See `MERGE.md` for the strategy, the attribution notice, and the known gaps.

## Firmware integrity is its own subsystem

An OS scan runs on the machine it judges, so it cannot certify the hardware hosting
it. `qvault/firmware_integrity.py` ranks anchors by independence and enforces that a
verdict may not be stronger than its anchor:

| Anchor                   | Establishes                                         |
| ------------------------ | --------------------------------------------------- |
| OS-mediated read         | **nothing**                                         |
| Firmware measures itself | boot chain (hypothesis)                             |
| TPM quote                | boot chain, DXE, option ROM (**not** flash or CRTM) |
| Hardware boot ROM        | CRTM                                                |
| Out-of-band flash read   | flash image, CRTM, DXE, ME/EC                       |

Host trust needs `flash_image` and `crtm` at rank 3 or above, and the only route to
`flash_image` is out-of-band. `certify_host()` refuses on weaker evidence naming the
missing subject, and `os_scan_verdict()` returns `UNATTESTED` even when every module
matched.

## Isolating the components that interpret attacker bytes

`qvault/isolation.py` places the five untrusted components (evidence readers,
database parsers, indicator processing, report generation, AI-assisted analysis) and
refuses placements that cannot meet them:

| Component            | Zone         | Must not have                                     |
| -------------------- | ------------ | ------------------------------------------------- |
| Evidence reader      | enclave      | network, keys, model, vault write, report emit    |
| Database parser      | enclave      | the same                                          |
| Indicator processing | intel        | artifact read, **finding write**, whitelist write |
| Report generation    | presentation | artifact read, plaintext, keys, model             |
| AI analysis          | ai           | artifact read, plaintext, keys, finding write     |

Placement is validated rather than labelled, data flow is deny-by-default (plaintext
never leaves the enclave toward AI or reporting; keys flow only into the enclave), and
model output enters as an `Observation` graded `HYPOTHESIS`, never as a `Finding`.

## Every artifact carries eight mandatory elements

`qvault/provenance.py` refuses to build an envelope without all of them:

| Element                          | Enforced how                                                                                              |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Original-source identification   | kind, locator and identity all non-empty                                                                  |
| Acquisition timestamp            | positive integer milliseconds, UTC                                                                        |
| SHA-256 digest                   | **computed from the bytes**, never accepted from the caller; `verify()` re-hashes in constant time        |
| Acquisition method               | fixed vocabulary, and each method maps to an evidence plane                                               |
| Tool and reader versions         | both mandatory and separate: a capture bug and a parser bug need different remedies                       |
| Coverage and collection errors   | every error must state its effect; unobserved regions become telemetry gaps that lower finding confidence |
| Chain of custody                 | append-only, hash-chained, first event must be the acquisition; verification detects edits and reordering |
| Cryptographic protection at rest | authenticated ciphers only; `AES-256-CBC` and `none` are refused                                          |

## Five rules the tool cannot break

Enforced in `qvault/findings.py` by construction, not by review:

1. **Every finding has an evidence grade** — `Finding` refuses to construct without one.
2. **Every finding considers a plausible benign explanation** — including all-clear results.
3. **Missing telemetry lowers confidence** — computed as grade minus one step per gap,
   floor `UNKNOWN`. A gap can never raise a result.
4. **Detection and attribution are separate** — attribution cannot exceed detection,
   because you cannot be more certain who did it than that it happened.
5. **No device is ever called clean** — `clean` is not a value the verdict type can
   produce, and an unexamined critical surface forces `inconclusive`.

An unexcluded benign explanation caps a finding at `suspicious`: failing to rule out
the boring answer is not evidence of malice.

## What the evidence planes can and cannot establish

`qvault/limitations.py` models the four architectural limitations (live-state
visibility, firmware blind spots, baselines, indicator trust) as evidence planes
with a `forgeable_by_subject` property, so a claim's strength is computed from the
plane it rests on:

| Claim               | Plane                       | Defensible against an adversary |
| ------------------- | --------------------------- | ------------------------------- |
| Firmware integrity  | read via the subject's OS   | **no**                          |
| Firmware integrity  | read out-of-band (physical) | yes                             |
| Process existed     | live response               | **no**                          |
| Network contact     | wire observation            | yes                             |
| Behaviour is normal | baseline                    | **no**                          |
| Object is malicious | threat intel                | **no**                          |

Also included: `baseline_validity()` returns `unverified` when the compromise window
is unknown, never `valid`; `intel_trust()` reports three feeds sharing one upstream
as `circular`, not corroboration. The controls raise coverage; none of them raises
integrity. See `report/ARCHITECTURAL_LIMITATIONS.md`.

## Capability denial, and who enforces it

`qvault/containment.py` models the six denials (network, authentication services,
storage, compute, inter-network, decryption) as a function of the **plane** that
enforces them and the **posture** of the subject:

| Plane                    | Clean | OS compromised | Firmware compromised                     |
| ------------------------ | ----- | -------------- | ---------------------------------------- |
| Subject OS               | full  | **none**       | **none**                                 |
| Hypervisor               | full  | full           | partial                                  |
| Fabric (switch/VLAN ACL) | full  | full           | full, if every egress path is enumerated |
| Physical                 | full  | full           | full                                     |
| Cryptographic            | full  | full           | full                                     |

A plan built from host firewalls, ACLs and service shutdown reads as complete and
provides zero denial once the subject is compromised, because the subject decides
whether its own rules apply. `audit_claim()` takes a plan, a posture and the
capabilities you believe you denied, and reports which ones the plan does not
support. `assess()` never claims eradication.

## Network context as a policy selector

`qvault/netpolicy.py` maps an observed association (BSSID, SSID, EAP state) to a
collection, retention and custody policy. The BSSID is a **selector only** — it is
48 bits broadcast in every beacon and clonable in seconds, so it can never be or
seed a key. A test demonstrates why: two independent hosts hashing the same BSSID
land on identical bytes.

Because an evil-twin AP chooses its own BSSID, every disqualifier is checked
before any credit is given. Randomised BSSIDs, open or PSK-only networks, and EAP
without server-validation all fall to `untrusted`. Raising trust requires an
authenticated network *plus* corroboration the AP does not get to assert alone.
A hostile network yields the `forensic` policy: more evidence, tighter custody,
no egress.

## Comparing a suspect image against the OEM reference

LoJax is catchable by inventory (it adds `SecDxe` and removes `NtfsDxe`).
MoonBounce is not: it patches a legitimate `CORE_DXE` in place, appends an
**unnamed section** after `.reloc`, and turns five bytes at the head of three boot
services into a `call`. The file GUID, name, type and volume layout are unchanged,
so only a per-section byte comparison sees it.

```bash
python -m qvault fwdiff --reference oem_image.bin --suspect dump.bin
```

It reports modules added/removed, per-section hash changes, unnamed sections,
write-and-execute sections, entry-point prologue changes, and any of the
MoonBounce immediates (including `0x6F4EB841`, the original `ExAllocatePool`
prologue the implant compares against). Exit code 0 means clean.

Limits, stated in the module docstring: compressed sections are compared as
opaque bytes, TE images are detected but not section-parsed, and a byte diff can
tell you a module changed but not which function, without symbols.

## What the tests prove

`python -m pytest qvault/tests -q` exercises, among others:

- byte-exact round trip across empty / sub-chunk / exact-chunk / multi-chunk inputs;
- plaintext never appears inside the sealed object;
- a single flipped ciphertext bit is caught by both `verify` and decryption;
- truncated ciphertext and mismatched metadata (AAD) are rejected;
- one share is not enough (quorum enforced), two shares are;
- a requester cannot approve their own retrieval;
- retrieval outside a marked enclave is refused;
- retrieved plaintext is mode `0400`, never executable;
- audit edits break the hash chain, and truncation breaks the signed checkpoint;
- triage recognises a flash descriptor and FV header without parsing them, and
  phantom regions can no longer be produced from synthetic input;
- orphan objects (bytes with no envelope) are reported as errors;
- `fwdiff` detects an added module, a removed module, a modified section, an
  unnamed appended section, a prologue replaced by a `call`, and a W+X section;
  and malformed or truncated input never raises.

## Non-goals and honest limits

- **Encryption does not disinfect.** A machine whose firmware is already
  compromised stays compromised. The vault preserves the evidence; reflashing,
  hardware replacement and trust re-establishment are separate procedures.
- **The vault cannot defend a compromised ingestion host.** Code that runs
  before encapsulation has already won. See the failure analysis in the report;
  the fix is architectural (disposable read-only acquisition appliance), not
  cryptographic.
- **The local filesystem is not WORM.** For real custody, place `objects/` and
  `envelopes/` on compliance-mode object storage or an append-only snapshot, and
  anchor checkpoints externally (RFC 3161, transparency log, paper record).
- **No deep parsing.** Deliberately. Deep firmware parsing belongs in the
  enclave, on a decrypted copy, under a parser that is assumed exploitable.

## Safety

This repository contains no malware, no exploit code and no persistence
mechanism. Test fixtures are synthetic byte strings. Do not point the tooling at
live samples outside an authorised, isolated analysis environment.

Defensive research, dual-use by nature; published so defenders can adopt it.

# qvault — a cryptographic quarantine vault for firmware evidence

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

## Read this before trusting any claim in here

This project performed **no independent reverse engineering**. No sample was
obtained, unpacked or executed. Every statement about LoJax, MoonBounce and
BlackLotus is a reconstruction from published vendor analysis, and every
signature in `qvault/fwdiff.py` is derived from documented bytes without live
validation.

- [`report/EVIDENCE_POLICY.md`](report/EVIDENCE_POLICY.md) — the three rules this
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

| Mechanism | Threat it addresses | Why not something simpler |
|---|---|---|
| Encrypt at ingestion, streaming | Accidental execution, casual inspection, backup/AV crawlers touching the sample | A password-protected zip still writes a plaintext temp file during `zip` |
| Fresh DEK per object | One leaked key burns one sample, not the vault | A single vault key means any single compromise is total |
| KEK split K-of-N (Shamir, GF(256)) | Compromise of the vault host or any one custodian | A KEK in one file is one credential away from full disclosure |
| Dual-control approvals, requester ≠ approver | Insider misuse, rushed "just decrypt it" | Logging alone does not prevent, only records |
| Enclave sentinel directory | Decrypting straight into a workstation or production share | Path checks alone are bypassable by symlink or mount games |
| Chunked AEAD with metadata binding | Silent corruption, sample swapping, truncation | A plain SHA-256 manifest cannot tell you *which* bytes changed or stop a swap |
| Content-address by ciphertext hash | Plaintext hash as a confirmation oracle | Content-addressing by plaintext hash leaks "do you have sample X?" |
| Hash-chained audit + signed checkpoints | Log editing, entry deletion, history rewrite | A normal log file is editable by anyone with write access |
| Inert triage (bounded reads only) | Parser exploitation at the boundary | Deep FFS/PE parsing at ingestion turns the vault into an attack surface |

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest qvault/tests -q      # 187 tests, ~0.45s
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

## Every artifact carries eight mandatory elements

`qvault/provenance.py` refuses to build an envelope without all of them:

| Element | Enforced how |
|---|---|
| Original-source identification | kind, locator and identity all non-empty |
| Acquisition timestamp | positive integer milliseconds, UTC |
| SHA-256 digest | **computed from the bytes**, never accepted from the caller; `verify()` re-hashes in constant time |
| Acquisition method | fixed vocabulary, and each method maps to an evidence plane |
| Tool and reader versions | both mandatory and separate: a capture bug and a parser bug need different remedies |
| Coverage and collection errors | every error must state its effect; unobserved regions become telemetry gaps that lower finding confidence |
| Chain of custody | append-only, hash-chained, first event must be the acquisition; verification detects edits and reordering |
| Cryptographic protection at rest | authenticated ciphers only; `AES-256-CBC` and `none` are refused |

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

| Claim | Plane | Defensible against an adversary |
|---|---|---|
| Firmware integrity | read via the subject's OS | **no** |
| Firmware integrity | read out-of-band (physical) | yes |
| Process existed | live response | **no** |
| Network contact | wire observation | yes |
| Behaviour is normal | baseline | **no** |
| Object is malicious | threat intel | **no** |

Also included: `baseline_validity()` returns `unverified` when the compromise window
is unknown, never `valid`; `intel_trust()` reports three feeds sharing one upstream
as `circular`, not corroboration. The controls raise coverage; none of them raises
integrity. See `report/ARCHITECTURAL_LIMITATIONS.md`.

## Capability denial, and who enforces it

`qvault/containment.py` models the six denials (network, authentication services,
storage, compute, inter-network, decryption) as a function of the **plane** that
enforces them and the **posture** of the subject:

| Plane | Clean | OS compromised | Firmware compromised |
|---|---|---|---|
| Subject OS | full | **none** | **none** |
| Hypervisor | full | full | partial |
| Fabric (switch/VLAN ACL) | full | full | full, if every egress path is enumerated |
| Physical | full | full | full |
| Cryptographic | full | full | full |

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

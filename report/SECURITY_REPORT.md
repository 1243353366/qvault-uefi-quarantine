# Security report - qvault 0.13.8

This is the point-in-time security report for release **0.13.8**. It describes what
the system enforces, what it can prove about itself, and what remains open. It is generated
from the tree it describes: the counts, the gate list and the grade census are read at build
time, so a stale claim fails the build rather than sitting in a document.

> **Scope.** Defensive firmware forensics: acquisition, quarantine, evidence grading and
> containment for UEFI-resident malware. No live host, no real SPI flash and no physical
> programmer were available, so every hardware-plane statement is graded accordingly and
> gathered in [the limitations page](ARCHITECTURAL_LIMITATIONS.md).

## 1. What was verified, and how

The release passes **17 gates**, each of which refuses the push that would
break it. The gates are not a checklist; each one exists because something went wrong first:

| Gate | Checks             |
| ---- | ------------------ |
| G1   | unit tests         |
| G2   | smoke              |
| G3   | evidence ledger    |
| G4   | wire contract      |
| G5   | single owner       |
| G6   | no clean state     |
| G7   | denial invariance  |
| G8   | scope gate         |
| G9   | behaviour matrix   |
| G10  | telemetry map      |
| G11  | in-the-wild set    |
| G12  | documentation site |
| G13  | version source     |
| G14  | internal links     |
| G15  | residency taxonomy |
| G16  | table alignment    |
| G17  | denial model       |

The unit suite is run by G1 and the end-to-end lifecycle by G2. CI repeats the whole set on
two Python versions alongside a wheel install outside the checkout, so the evidence is
reproducible without trusting the author's machine.

## 2. Evidence base

The claims ledger holds **172** claims. Every one carries a source, a locator, a tag and
a falsifier. The census at this release:

| Tag          | Claims |
| ------------ | ------ |
| CONFIRMED    | 160    |
| CORROBORATED | 0      |
| INFERRED     | 9      |
| HYPOTHESIS   | 2      |
| UNKNOWN      | 1      |

| Verification method | Claims |
| ------------------- | ------ |
| independent         | 121    |
| none                | 51     |

**51 claims carry no independent verification.** They are cited to a source
and graded no higher than the source supports, and they are counted here rather than
rounded away: a report that only lists verified claims is a report about the easy half.

68 sources are catalogued and individually linked on the
[citations page](../CITATIONS.md).

## 3. What the system enforces

Three denial postures, each recorded with the condition that ends it:

| Posture           | Denies                                                                | Ceiling on a good plane | Ends when                                                                                                                                          |
| ----------------- | --------------------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `deny_access`     | the payload is usable: the bytes are there, the key is not            | CORROBORATED            | the key becomes available inside the attacker's reach, at which point the payload is as readable as it was before                                  |
| `deny_capability` | the code reaches what it needs: execution, communication, persistence | CORROBORATED            | the isolation is lifted, or the attacker finds a path that was never in the enumeration, and the capability returns without any alarm having fired |
| `deny_execution`  | the code starts: on disk, unverified, and unable to run               | CORROBORATED            | the verifier's root is compromised, or the allow list is stale against a signed-but-hostile component, and execution is permitted by policy        |

No denial claim reaches CONFIRMED and gate G17 enforces that. Inability is inferred from
the absence of a success, and this project does not promote absence.

The full model, including what each posture does not do, is
[the denial model page](DENIAL_MODEL.md).

## 4. Open findings

These are live limits, not historical notes. Each carries its grade and the observation
that would close it.

### A1 - Host trust gap (CONFIRMED)

Every control that runs on the target is void once the kernel or the boot chain below it is compromised, which is exactly the case a bootkit creates.

**Would be closed by:** A control exercised on a host with a malicious kernel that still reports success.

### A5 - Self-scan cannot establish its own integrity (CONFIRMED)

A tool that reads its own stack through that stack cannot prove the reading. Self-scan detects accidental damage and casual tampering, not a capable adversary.

**Would be closed by:** A self-scan passing on a host where the tool's own binary was modified.

### A7 - No identity binding for dual control (CONFIRMED)

Two approvals are required and both are recorded, but an approver name is not bound to a verified principal, so one person with two keys satisfies the check.

**Would be closed by:** A documented case where one operator produced both approvals.

### H1 - Hardware protection state in emulation (HYPOTHESIS)

OVMF has no SPI controller registers, so a write-protected flash state observed in QEMU is a property of the emulator, not of firmware.

**Would be closed by:** The same read on real hardware disagreeing with the emulated result.

### H4 - Protection state reading methods (HYPOTHESIS)

Software readers of SPI protection bits run on the platform they are measuring; a compromised firmware can report protected while unprotected.

**Would be closed by:** An out-of-band programmer reading protection bits that contradict the software reader.

### D2 - Retroactive encryption has a boundary (CORROBORATED)

Encrypting evidence denies access from the moment the key is withheld. It does not undo a key or a plaintext copy taken before that moment, and it does not touch a bootkit that needs no payload to decrypt.

**Would be closed by:** Evidence recovered from a snapshot taken before the key was withheld.

## 5. What this report does not claim

It does not claim any host is clean, any implant is absent, or any hardware protection
is active on real firmware. Absence of a finding is not evidence of absence: the
system distinguishes *no finding* from *no observation*, and only the second is a gap
in the evidence.

It also does not claim the denial postures are independent of each other. Three controls
enforced by one authority are one control, and the composition table in the denial
model says so.

## 6. Reproducing this report

```bash
git clone https://github.com/1243353366/qvault-uefi-quarantine
cd qvault-uefi-quarantine
pip install -r requirements-dev.txt
python -m pytest qvault/tests -q
python3 tools/gates.py
python3 tools/gen_security_report.py
```

Release artifact: `v0.13.8`. The gate list, the census and the posture ceilings
above are regenerated from the code at every build.

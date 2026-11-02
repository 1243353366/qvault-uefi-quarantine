# Denial model: three postures and the conditions that end them

Three ways to deny an attacker, kept apart because they fail differently. Each one is a
statement about an adversary's *inability*, and inability is the hardest claim to establish
from inside the system being attacked. So each posture carries its non-claims and the
condition under which the denial ends.

> These are not detections and not verdicts. A posture is a control. This page grades the
> claim that the control is holding, and records what it cannot do. The verdict engine
> remains single-owner; nothing here decides whether a host is compromised.

## The three postures

| Posture           | Denies                                                                | Load-bearing control                                                               | Ceiling      | Availability cost                                                                                                             |
| ----------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `deny_access`     | the payload is usable: the bytes are there, the key is not            | key custody, plus the proof that the key never lived beside the ciphertext         | CORROBORATED | lose the key and the evidence or the data is gone; this is the one posture whose failure mode is unrecoverable by design      |
| `deny_capability` | the code reaches what it needs: execution, communication, persistence | the completeness of the resource enumeration, which is ours and not the attacker's | CORROBORATED | reduced observability: the same boundary that starves the malware also starves the telemetry that would have caught it        |
| `deny_execution`  | the code starts: on disk, unverified, and unable to run               | the verification root being outside the control of the code being verified         | CORROBORATED | a wrong allow list or a bad revocation update bricks the machine; the denial is only as good as the update pipeline behind it |

## `deny_access`

**Denies.** the payload is usable: the bytes are there, the key is not.

**Load-bearing.** key custody, plus the proof that the key never lived beside the ciphertext.

**Stops:**

- a payload encrypted before an attacker arrived being read afterwards
- exfiltration of the ciphertext turning into execution, while the key is withheld
- an analyst or an automated tool decrypting evidence without quorum

**Does not stop:**

- a key that was already copied while it was available
- plaintext an attacker kept before encryption happened
- an implant that never needed the payload: a bootkit in SPI flash is not encrypted
- the attacker waiting: access is denied for a window, not for good

**Denial ends when:** the key becomes available inside the attacker's reach, at which point the payload is as readable as it was before.

**Cost of being wrong:** lose the key and the evidence or the data is gone; this is the one posture whose failure mode is unrecoverable by design.

## `deny_capability`

**Denies.** the code reaches what it needs: execution, communication, persistence.

**Load-bearing.** the completeness of the resource enumeration, which is ours and not the attacker's.

**Stops:**

- a driver talking to a device it is no longer on the same bus as
- an implant beaconing out of a host with no route, or a port that is down
- persistence across reboot when the write target is protected below the OS

**Does not stop:**

- a capability we did not think of; isolation only removes what is on our list
- code that still runs and adapts inside the reduced space
- an attacker who moves to a host that is not isolated
- detection: a quiet implant on an isolated host is quieter, not absent

**Denial ends when:** the isolation is lifted, or the attacker finds a path that was never in the enumeration, and the capability returns without any alarm having fired.

**Cost of being wrong:** reduced observability: the same boundary that starves the malware also starves the telemetry that would have caught it.

## `deny_execution`

**Denies.** the code starts: on disk, unverified, and unable to run.

**Load-bearing.** the verification root being outside the control of the code being verified.

**Stops:**

- an unsigned or revoked boot component on a chain anchored in hardware
- a userland binary outside the allow list, where the kernel enforcing it is itself trusted
- a bootkit whose revocation has actually been applied

**Does not stop:**

- code verified on a chain the attacker controls below the verifier
- a signed component that is legitimately signed and malicious, which verification cannot see by construction
- a revocation nobody shipped: an unapplied dbx denies nothing
- anything already running before verification was enabled

**Denial ends when:** the verifier's root is compromised, or the allow list is stale against a signed-but-hostile component, and execution is permitted by policy.

**Cost of being wrong:** a wrong allow list or a bad revocation update bricks the machine; the denial is only as good as the update pipeline behind it.

## What each enforcement plane can support

A control is only as strong as the plane it sits on. A plane inside the thing being
attacked is a preference, not an enforcement.

| Plane          | Ceiling      | Why                                                                                        |
| -------------- | ------------ | ------------------------------------------------------------------------------------------ |
| `hardware`     | CORROBORATED | the host cannot rewrite it without physical access                                         |
| `external_key` | CORROBORATED | the key is outside the host's trust domain, so a host compromise is not a key compromise   |
| `out_of_band`  | CORROBORATED | a different machine or a port the host cannot reprogram                                    |
| `supply_chain` | CORROBORATED | a signed revocation that has actually been applied                                         |
| `in_band`      | INFERRED     | policy running on the host it constrains, so compromising the host compromises the control |
| `absent`       | UNKNOWN      | asserted with nothing behind it                                                            |

No plane reaches CONFIRMED, and the gate refuses one that tries. CONFIRMED is for
things present in the evidence; "the attacker could not" is inferred from the
absence of a success, and absence of evidence is what this project refuses to
promote. The strongest a denial claim gets is CORROBORATED.

## Three postures, one mistake

| Combination                                    | What it means                                                                                                                                 |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| deny_access + deny_execution on the same plane | collapses into one control: a key held by the same authority that signs the allow list is one compromise away from both                       |
| deny_capability + deny_execution across planes | independent: starvation is enforced on the network, execution on the boot chain, so one compromise does not lift the other                    |
| all three on the target OS                     | none of them hold against a kernel-level compromise; they describe a machine that is still trusted, which is the assumption a bootkit removes |

The independence test is the plane, not the label. Three denials enforced by one
authority are one denial: a key held by the same service that signs the allow list
is a single compromise away from both.

## Worked against the three families

| Family     | Posture that applies                                                             | Plane                  | Grade                                                                 | What it does not give you                                                                              |
| ---------- | -------------------------------------------------------------------------------- | ---------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| LoJax      | `deny_capability` (SPI write protection), then `deny_execution`                  | hardware               | CORROBORATED                                                          | an implant already in flash keeps booting: protection stops the write, not the resident                |
| MoonBounce | `deny_capability` on the flash descriptor, `deny_access` for the collected image | hardware, external_key | CORROBORATED                                                          | the dump is only as good as the programmer that read it, and an encrypted archive is not a trusted one |
| BlackLotus | `deny_execution` by revocation                                                   | supply_chain           | INFERRED until the revocation is actually applied, CORROBORATED after | a signed-but-later-revoked bootloader still runs on every machine that never applied the update        |

BlackLotus is where the supply-chain plane is easiest to mistake for a hardware one. The
control is real, but it lives in an update pipeline: the denial holds on the machines
that shipped the revocation and nowhere else. That is why the grade depends on
application, not on the advisory existing.

## What all three share

Every posture above assumes something below it is intact. Deny execution assumes the
verifier's root is trusted; deny capability assumes the enumeration of what the code
needs is complete; deny access assumes the key was never where the payload was. A
bootkit voids the in-band versions of all three at once, which is the same limit the
architectural limitations page records as A1 and A5.

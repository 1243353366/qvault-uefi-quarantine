# Trust model

Six weaknesses are treated as must-fix before deployment. Only some of them are closable
in code. The rest are properties of where the software runs, and the honest response is to
refuse the stronger claim rather than to invent a control that cannot exist.

Status terms used below:

- **Enforced** - the code refuses the unsupported conclusion and the refusal is tested.
- **Architectural** - no amount of code closes it. The code can only cap its own claims
  and require evidence it cannot produce.
- **Deployment** - a property of the installation, checked by the code when declared and
  otherwise assumed.

## Summary

| #   | Gap                  | Status        | What the code does now                                                                          | What it still cannot do                             |
| --- | -------------------- | ------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| 1   | Host trust gap       | Architectural | Caps every conclusion at the ceiling of its best evidence class and refuses the rest            | Prove the integrity of the host it is running on    |
| 2   | Self-scan            | Architectural | `self_report` supports no conclusion at all, so a self-scan cannot produce a grade              | Certify the evidence source from inside that source |
| 3   | Oracle in denials    | Enforced      | Coarse, byte-identical refusal for unprivileged callers; detail only behind a granted principal | Authenticate that principal (see assumption A1)     |
| 4   | Separation of duties | Enforced      | Refuses an identity holding observer and verifier roles in the same pipeline                    | Stop an operator wiring it anyway outside the API   |
| 5   | Local storage        | Deployment    | Refuses an append-only custody claim on non-WORM storage                                        | Make a local filesystem append-only                 |
| 6   | Live samples         | Enforced      | Refuses live capture unless the acquisition path is isolated and attested                       | Verify that isolation from the inside               |

## 1. Host trust gap

A privileged read on the subject cannot establish the integrity of the subject: whatever
compromised the firmware could be what answers the read. This is stated in the README and
it is not a defect, it is the shape of the problem.

Enforcement lives in `separation.grade_ceiling` and `assert_claim_supported`. Each
evidence class has a ceiling, and a claim above it raises `EvidenceCeilingError` naming the
class that would be needed:

| Evidence class                                               | Strongest grade supported    |
| ------------------------------------------------------------ | ---------------------------- |
| `self_report`                                                | none: supports no conclusion |
| `peer_claim`                                                 | `HYPOTHESIS`                 |
| `independent_measurement` (physical flash read, bus capture) | `CORROBORATED`               |
| `signed_manifest`                                            | `CORROBORATED`               |
| `hardware_anchor` (TPM quote, DICE)                          | `CONFIRMED`                  |

So a host-mediated scan of an image can support `INFERRED` at best, a physical SPI read
can support `CORROBORATED`, and only a hardware-rooted measurement corroborating that read
reaches `CONFIRMED`. Volume does not substitute: fifty independent measurements of one
class still cap at that class.

## 2. Self-scan

`self_report` maps to no grade, so a component describing its own state cannot support any
finding. This is the machine-checkable form of "the engine cannot certify itself" in the
README. A self-scan is still useful for metadata and internal consistency; it is simply
not evidence of trust, and the model will not let it be graded as such.

## 3. Oracle-safe denials

The previous denial logic was an oracle. `DENY_UNKNOWN_RESOURCE` against
`DENY_INSUFFICIENT_CUSTODY` told an unauthenticated caller both that a resource existed and
which condition was close to passing, and the resource name was echoed back.

Now:

- The default answer is `{"allowed": false, "denial": "refused", "remedy": ...}`, byte
  identical for a real resource, a forbidden one, and one that does not exist.
- Evaluation always runs the same rules first, so a refusal does not take a cheaper path
  than an allowed request.
- Detail requires a `Principal` with a name, a role and a granted `sees_detail` flag.
- Bulk results for unprivileged callers report only whether everything was allowed, not
  how many requests failed or which.

Residual: an allowed request still returns `allowed`, because a caller must know whether
to proceed. Probe-and-permit therefore reveals which operations are permitted, though never
why a refusal happened.

### Assumption A1

`Principal.sees_detail` is not authenticated by this code. Until a deployment wires it to
its own authentication, every principal is unverified and only the coarse path is safe.
This is recorded in the claims ledger with that wording rather than described as solved.

## 4. Separation of duties

Roles were separated per component but a pipeline could still assign one identity several
of them, which is how a single compromised host both observes and decides.
`pipeline_conflicts` refuses these pairs:

| Pair                       | Why                                                  |
| -------------------------- | ---------------------------------------------------- |
| acquisition + verification | the observer would be judging what it observed       |
| analysis + verification    | the analyst would be verifying its own parsing       |
| storage + verification     | the holder would be certifying the evidence it holds |

The refusal names the shared identity. A fully separated pipeline is
`acquisition -> analysis -> storage`, with `verification` held by a fourth identity on a
different host.

## 5. Local storage

`assert_custody_claim` refuses an append-only claim on `not_worm` storage and says what to
do instead: object-lock buckets or a compliance-mode mount. The audit chain detects
tampering; it does not prevent rewriting, and the code no longer implies otherwise.

## 6. Live samples

`assert_scope` refuses `live_capture` unless the acquisition path is both isolated and
attested, and names which of the two is missing. Synthetic fixtures need neither.

## What a pilot should look like

1. Acquire out of band: physical read or an attested acquisition path.
2. Analyse in a separate identity realm from the one under examination.
3. Verify from a fourth identity, on a different host, against a reference the subject
   cannot write.
4. Store on WORM media, and claim append-only only there.
5. Report observed and inferred separately, with the evidence class behind each grade.
6. Refuse the verdict when the evidence class cannot carry it, and say which class would.

## The honest split

Two kinds of problem, and they should not be described in the same voice.

**Cheap and reproducible**, at the authorization boundary: one constant-shaped refusal, a
single public denial code, unknown treated as forbidden, denials recorded rather than
returned, evaluation failure denying, and monotonicity checked against an explicit
allowance table. All of it black-box, unit-testable, and now tested in
`test_policy_semantics.py` (25 tests).

**Architectural**, and not patchable: a host cannot certify itself, a self-scan is not
proof, out-of-band evidence is required for a firmware claim, and a local filesystem is not
WORM. The code's contribution there is limited to refusing the stronger conclusion and
naming what would support it. Calling those "bugs" would misdescribe them, and claiming
they are fixed because a test passes would be worse.

## The probe contract

`qvault/probe.py` is the instrument side of the boundary, and it is deliberately unable to
answer anything but "what did I observe":

| Requirement                      | How it is met                                                                          | How it is tested                                                      |
| -------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| No new way to learn hidden facts | One token per request; identical for forbidden and absent                              | `test_a_forbidden_resource_and_a_missing_one_are_indistinguishable`   |
| No behaviour on the target       | No connections, no execution, no files                                                 | source scan for socket/urllib/subprocess/eval/exec/open; empty tmpdir |
| No remote resource use           | Pure local evaluation of an existing decision                                          | no imports that can reach out                                         |
| No unauthorised distinctions     | Closed token vocabulary; gate labels only for the caller's own context                 | `test_the_vocabulary_is_closed`                                       |
| Bounded                          | `Budget`, one attempt, no retries or recursion                                         | `test_a_second_call_gives_unknown_not_another_attempt`                |
| Refuses on ambiguity             | Missing attestation outranks a denial; incomplete context is `PARTIAL`, never "absent" | `test_incomplete_context_is_partial_not_absent`                       |
| No timing signal                 | Every gate computed for every request                                                  | evaluation trace plus a 3x timing bound                               |

What it cannot do: prove the host, establish an evidence class it was not given, or make a
local filesystem append-only. Those remain in the architectural column.

## Running the checks

```bash
python3 -m pytest qvault/tests/test_trust_model.py -q    # 38 tests
bash tools/reproduce.sh                                   # every gate
```

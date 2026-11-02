# Operating model: Scrum for the work, gates for the safety

Scrum runs the backlog. It does not run the safety model, and it does not get a vote on
whether a refusal may leak information.

## What Scrum is used for

Backlog, sprinting, acceptance criteria, release gates, and progress visibility. Each sprint
ends with evidence rather than a demo: `python3 tools/gates.py` is the acceptance record, and
a red gate is a refusal, not a scheduling problem.

## What Scrum is not used for

Velocity may not override:

- **refusal on ambiguity** — an unanswerable question stays unanswerable, and a sprint
  deadline does not convert it into a "no finding";
- **oracle safety** — a denial that reveals whether a resource exists is a defect regardless
  of how much it would cost to fix before the demo;
- **attack-surface validation** — no merge that adds a mechanism, an adapter or an input
  path without a threat-model note and the tests that fail-closed behaviour requires.

If a gate blocks a release, the release moves. The gate does not.

## Epics

| Epic | Scope | Where it lives | Evidence |
|------|-------|----------------|----------|
| E1 Detection contract | mechanism descriptors, four result classes, no clean state | `qvault/persistence.py` | `test_persistence.py` (40) |
| E2 Policy refusal and oracle safety | one public code, deny-and-record, fail closed, uniform work | `qvault/netpolicy.py`, `qvault/probe.py` | `test_policy_semantics.py`, `test_probe.py` |
| E3 Attestation and host trust | evidence classes, ceilings, self-report refusal | `qvault/separation.py`, `qvault/grading.py`, `qvault/firmware_integrity.py` | `test_module_trust.py`, `test_policy_semantics.py` |
| E4 Persistence mechanism coverage | the eleven mechanisms, observability boundaries | `qvault/persistence.py` | `test_persistence.py` |
| E5 Ledger and evidence validation | claim tags, bibliography, CSV contract | `report/CLAIMS_LEDGER.csv`, `tools/check_claims.py` | `test_persistence.py` ledger test |
| E6 Attacker behaviour coverage | behaviour to control, with gaps named | `qvault/behaviors.py`, `report/THREAT_BEHAVIOR_MATRIX.md` | `test_behaviors.py`, gate G9 |

## The polyglot boundary

Language diversity is safe at the edges and unsafe at the decision. Concretely:

| Component | Language | Rule |
|-----------|----------|------|
| Verdict engine (`netpolicy`, `grading`) | Python, single owner | May not shell out, may not import an adapter, may not delegate a decision to another runtime |
| Detection adapters (`persistence`, `probe`, `contract`) | Python | May build payloads; may not compute policy or grade arithmetic of their own |
| Wire contract (`contract/verdict.schema.json`) | JSON Schema | The only interface other runtimes see |
| Edge tooling (`adapters/verdict_lint.mjs`, `tools/*.py`, shell) | any | May read and report; holds no trust decision |

The boundary is enforced, not documented: `tools/gates.py` G5 fails if an engine module
contains a process, socket or shell call, or if the engine imports an adapter. A Go collector
or a shell report generator can be added later and cannot weaken this, because it only ever
holds a payload.

## The shared contract

`contract/verdict.schema.json` describes one payload: mechanism, basis, attestation state,
observed signals and counts, verdict token, cap grade, denial codes, remedy, statement.

Two properties are structural:

- A policy payload has a `subject.resource` field that is always `null`. The type has no
  place to echo what the caller asked about, so a refusal cannot become a probe.
- `denial_codes` is a closed vocabulary with exactly one public value, so no adapter can
  invent the richer taxonomy that would tell an attacker which gate nearly passed.

Validation runs in two runtimes (`qvault/contract.py` and `adapters/verdict_lint.mjs`), and
G4 fails if either accepts a payload the other rejects, or if the node adapter accepts a
payload with no remedy.

## Sprint-end checklist

| Gate | Question |
|------|----------|
| G1 | Does the suite pass? |
| G2 | Does the end-to-end lifecycle still work? |
| G3 | Does every claim have a source, a tag, a status and a falsifier? |
| G4 | Do both layers emit payloads the schema accepts, in both runtimes? |
| G5 | Is the decision still single-owner and in-process? |
| G6 | Can the persistence layer still report a clean result? (It must not.) |
| G7 | Is a refusal identical across forbidden, absent and empty resources? |
| G8 | Is a live capture still refused without isolation and attestation? |
| G9 | Does every behaviour still resolve to real code, with the matrix current? |

Merge requires G1 through G9. Nothing here is advisory.

## Status

Scrum-wise: E1, E2, E4 and E5 are implemented and gated; E3 is implemented for the evidence
model but blocked on hardware for the attestation half (`report/HARDWARE_TEST_QUESTIONS.md`).
The architecture work that is not patchable at all — a host certifying itself, a local
filesystem being append-only — remains in `report/TRUST_MODEL.md` and is not claimed as done.

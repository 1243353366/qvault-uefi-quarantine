# Contributing

The rules here exist because this project's only real asset is that its claims can be checked.

## A claim is a row, not a sentence

Every factual claim about malware, firmware or this tool goes into `report/CLAIMS_LEDGER.csv` with
four required values:

- `bib` — a numbered source, listed in `CITATIONS.md`.
- `locator` — where in that source, specifically.
- `tag` — one of `CONFIRMED`, `CORROBORATED`, `INFERRED`, `HYPOTHESIS`, `UNKNOWN`.
- `falsifier` — the observation that would break the claim.

Gate G3 fails the build if any of those is missing. A pull request that adds a claim without a
falsifier is rejected without discussion, because a claim that cannot fail is not a claim.

## Grades are earned, not chosen

`CONFIRMED` requires **independent verification**: a second source, or a measurement that does not
derive from the first. A single vendor blog post is `CORROBORATED` at best, however authoritative it
sounds. A hardware-plane claim needs an out-of-band anchor, because software reading protection bits
on the machine it is measuring is not evidence about that machine.

`CLEAN` is not a grade. Absence of a finding is not evidence of absence, and code that reports it is
rejected.

## What will be rejected

- A detector that reports `CLEAN` because telemetry was missing rather than because it was examined.
- Offensive capability: a new implant, a bootkit, a bypass, a patched payload, a technique that only
  helps the attacker. This stays defensive.
- Malware samples in the tree. The repository ships zero binaries by policy.
- A new parser of external input without a matching entry in `report/TOOLING_RISK.md`; a test fails
  if a module takes `bytes` and is not registered.
- A claim upgraded in grade without new evidence.

## Before you open a pull request

```bash
pip install -r requirements-dev.txt
python -m pytest qvault/tests -q
python3 tools/gates.py          # all seventeen, and the pre-push hook runs them anyway
bash tools/install_hooks.sh     # once, to wire the hook
```

`tools/gates.py` exits non-zero on any failure, and `set -o pipefail` matters: a `| tail` once hid a
nonzero exit and let a broken commit reach `main`. See `report/DEFECT_LOG.md` for what each gate cost
to learn.

## Structure that is not up for grabs

The verdict engine has a single owner by design, and adapters talk to it through
`contract/verdict.schema.json`. A pull request that lets an adapter write verdicts directly will be
declined even if the tests pass: the isolation is the security property.

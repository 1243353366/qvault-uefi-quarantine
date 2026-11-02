# Reproducing the release assessment

A fresh checkout needs CPython 3.11 and the pinned dependencies. Nothing else: no network
access, no vendor account, no prior state.

```
git clone <repo> && cd qvault-uefi-quarantine
python3 -m pip install -r requirements-lock.txt
tools/reproduce.sh
```

`reproduce.sh` runs every gate in order and stops at the first disagreement.

## What a correct run prints

| Gate | Expected |
|------|----------|
| `python3 -m qvault --version` | `qvault 0.9.0` |
| `pytest qvault/tests -q` | 465 passed |
| `tools/smoke.py` | SMOKE OK: 62 checks passed |
| `tools/check_claims.py` | OK: every claim has a source, a tag, a status and a falsifier |
| `tools/gen_fingerprints.py` | no diff against `report/FINGERPRINTS.md` |
| `pillars.audit()` | 8 capabilities, 0 with a required gap |

## Using the numbers honestly

These counts describe *this* tree. They are not a security claim: the capability map lists
every remainder, and `report/CLAIMS_LEDGER.csv` records which claims are independently
verified and which are reasoning over secondary sources.

If a gate disagrees with the table above, the tree is not the release. Do not adjust the
table.

## Installation as a package

`pip install .` installs `qvault`, the CLI entry point and the pinned `vendor` tree. The
vendored detection engine must ship with the package: `qvault/zbt_bridge.py` raises an
explanatory ImportError if `vendor/zbtriage` is missing rather than failing obscurely.

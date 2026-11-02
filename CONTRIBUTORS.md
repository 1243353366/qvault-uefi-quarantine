# Contributors and prior work

## This repository

The QVault work in this repository: architecture, code, tests, and the reports under
`report/`.

## Vendored or referenced work

- **Google Project Zero** — `0days-in-the-wild`. The reference set in `vendor/p0_0days/` is a
  derived index of their root-cause analyses, Apache-2.0, pinned at commit
  `e21be4bb01c617736d35350fc2f64cd2a42a3721`. Their corpus and their analyses are their work;
  this repository only indexes it.
- **Zero-Breach-Toolkit** — vendored previously as a pinned snapshot with attribution in the
  ledger.
- **MITRE ATT&CK** — technique identifiers and vocabulary used throughout `qvault/behaviors.py`
  and `qvault/telemetry.py`.
- **SigmaHQ** — hunting rules cited by identifier in `qvault/telemetry.py`.
- **Tech Zealots (S. Daulaguphu)** — the persistence mechanism list that `qvault/persistence.py`
  implements as a detection contract.

## A note on what "collaboration" can mean here

Google Project Zero is an organisation, and GitHub only supports user accounts as outside
collaborators, so an invite to `googleprojectzero` is not possible and was refused with
"not a user". Collaboration with them properly means either a pull request to their repository
or a named individual accepting an invitation. Attribution here does not imply their
endorsement, and no invitation is pending.

# Credits

## Zero-Breach-Toolkit — the detection engine

The indicator engine, its fourteen-class evidence taxonomy (`on-disk`, `persistence`,
`execution-record`, `contacted`, …), its module status vocabulary (`CLEAN` / `HITS` /
`PARTIAL` / `UNKNOWN`) and its doctrine — including the mandatory closing line
*"This is not a clean bill of health"* — are the work of
**[@interplains](https://github.com/interplains)**.

- Repository: https://github.com/interplains/Zero-Breach-Toolkit
- Release consumed: **v2.0.2**, commit `90148eae72b722b59fb4f191daf959b21a002bb0`
  (signed, GPG `9B4D575499AFA53C`), released 2026-11-01
- Licence: Apache License 2.0, preserved in `vendor/LICENSE` and `vendor/NOTICE`

This repository vendors `scan/zbtriage` unmodified behind an adapter. It does not
replace that work and cannot stand without it: everything qvault adds — grading,
correlation, containment, verification — operates on observations the upstream engine
produces. Coverage of iOS, Android, Windows, macOS and Linux artifacts is upstream's,
including the encrypted iPhone backup support added in v2.0.1.

Indicator bugs, artifact-coverage gaps and detection false negatives belong upstream.
Grading, correlation and containment questions belong here.

## What qvault adds on top

| Area | Module |
|---|---|
| Evidence envelopes, provenance, coverage reporting | `provenance.py` |
| Grading of upstream detections against an adversary model | `zbt_bridge.py` |
| Temporal correlation with an independence rule | `correlate.py` |
| Authenticated encryption, immutable originals, audit chain | `crypto.py`, `store.py`, `audit.py` |
| Firmware and boot-chain verification with anchor ranking | `firmware_integrity.py` |
| Role separation and the ban on self-certification | `separation.py` |
| Resource budgets and credential revocation | `budgets.py`, `revoke.py` |

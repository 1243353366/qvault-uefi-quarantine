# Vendored upstream

Source: https://github.com/interplains/Zero-Breach-Toolkit
Commit: 5c86adf3994c004c26d6e54e751e0dd4c9964389 (v2.0.2 tree, `scan/zbtriage/` only)
License: Apache License 2.0 (see `LICENSE`, `NOTICE`)

## What was taken

The whole `scan/zbtriage` package: 51 modules, ~28k lines. Its detection logic,
evidence taxonomy (`EV_*`), module status vocabulary (`CLEAN/HITS/PARTIAL/UNKNOWN`)
and doctrine are used unmodified. Nothing in this directory is edited by qvault.

## Why a vendored snapshot instead of a fork

Forking would mean maintaining 28k lines of fast-moving upstream code while also
enforcing local rules, and the two would drift: upstream adds an evidence grade,
the local mapping silently treats it as unknown, and the discipline rots. A pinned
snapshot plus an adapter at the boundary keeps upstream authoritative for detection
and qvault authoritative for grading, and makes the seam testable.

## What was not taken

`build/`, `dist/`, `docs/`, `locales/`, `iocs/`, `skills/`, `tools/`, the CLI
(`cli.py`, `gui.py`, `__main__.py`) and the upstream test suite. Only the library
is vendored; running the scanner remains upstream's job.

## Refresh procedure

    git clone --depth 1 https://github.com/interplains/Zero-Breach-Toolkit /tmp/zbt
    rm -rf vendor/zbtriage && cp -r /tmp/zbt/scan/zbtriage vendor/zbtriage
    python3 -m pytest qvault/tests -q      # the bridge tests pin the vocabulary

If upstream adds or renames an evidence grade, `qvault/zbt_bridge.py` fails its
coverage test rather than silently grading the new artefact as benign.

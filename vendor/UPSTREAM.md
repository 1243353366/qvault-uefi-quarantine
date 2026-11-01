# Vendored upstream

Source: https://github.com/interplains/Zero-Breach-Toolkit by **@interplains**
Release: [v2.0.2](https://github.com/interplains/Zero-Breach-Toolkit/releases/tag/v2.0.2) = `90148eae72b722b59fb4f191daf959b21a002bb0` (signed, GPG `9B4D575499AFA53C`)
Snapshot taken at: `5c86adf3994c004c26d6e54e751e0dd4c9964389`
Equivalence: `git diff v2.0.2 5c86adf -- scan/zbtriage` is empty, so this snapshot is
the released library exactly, not a later development tree.
Tree digest: `sha256:7ace5ffe057e5c913c1c5be527c3f2802764a1bd19d0b3cbc6c2b77b54860b14` over the file list in `UPSTREAM.sha256`
License: Apache License 2.0 (see `LICENSE`, `NOTICE`)

## Credit

The detection engine, its evidence taxonomy and its doctrine are the work of
[@interplains](https://github.com/interplains). This repository consumes that work and
adds grading, correlation, containment and verification around it; it does not replace
it. If you find an indicator or artifact-coverage bug, it belongs upstream.

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

# Vendored: googleprojectzero/0days-in-the-wild

Derived index of Project Zero's root-cause analyses for 0-days exploited in the wild.

- Upstream: https://github.com/googleprojectzero/0days-in-the-wild
- Licence: Apache-2.0 (upstream `LICENSE`; this repository is also Apache-2.0)
- Pinned commit: `e21be4bb01c617736d35350fc2f64cd2a42a3721` (2026-08-10)
- Archive SHA-256: `6830725234b0a01fafa8c5fe5c865dce704bb9fb9f9d92453254f467e346d3c7`

## What is stored, and what is not

`index.json` is a *derived* index: for each RCA it records the CVE identifier, the year folder,
the heading title, the product, the disclosure date, the upstream path, the file size and the
SHA-256 of the upstream file. The 18 MB of source markdown is not vendored.

## Why an index rather than a copy

The project's rule is vendored, pinned snapshots with explicit audits. An index is enough to
hold upstream to a specific commit and to detect that a future snapshot differs, without
duplicating Google's documents here under a second authorship.

## Auditing an update

1. Fetch the archive for the new commit: `codeload.github.com/googleprojectzero/0days-in-the-wild/tar.gz/<sha>`
2. Record its SHA-256 in `index.json` and `SOURCE.md`.
3. Regenerate the index and diff `index.json`.
4. Review every added, removed and changed entry before committing; the per-file hashes make an
   edited RCA visible.

## Known upstream limitation

The tracking spreadsheet linked from the upstream README reports "Last updated: 2023-04-20" and
is not commit-pinnable, so it is not used. This index is derived from the pinned commit only,
and the corpus in that commit ends in 2024.

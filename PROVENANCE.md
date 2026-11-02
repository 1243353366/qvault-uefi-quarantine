# Provenance, verification and repackaging

This file answers the question a cautious reader asks about any tool that handles hostile input:
*how do I know the copy I have is the copy that was tested, and what may I do with it?*

## Licence and what must travel with it

Apache-2.0. You may use, modify and redistribute this, including commercially, provided you keep the
licence and attribution. Concretely, a redistribution must preserve:

- `LICENSE`,
- `NOTICE`, which carries the attribution for the vendored `zbtriage` engine and its upstream terms,
- `CREDITS.md` and `CONTRIBUTORS.md` for the portions they cover.

Apache-2.0 §6 does **not** grant rights to the project's marks. A fork is welcome; a fork that keeps
the name while changing how grading works is a problem, because the grades are the product. If you
change what a claim means, rename the thing.

## Verifying a release

Each release publishes the wheel plus a `SHA256SUMS` file. To check what you have:

```bash
curl -LO https://github.com/1243353366/qvault-uefi-quarantine/releases/download/vX.Y.Z/SHA256SUMS
sha256sum -c SHA256SUMS
```

And to tie an artefact back to a reviewed tree: the release notes name the commit, the commit has a
CI run that is public, and `tools/gates.py` reproduces the local half of that verification on your
own machine.

**What is not covered.** Tags and commits are **not cryptographically signed**: no signing key is
configured for this repository. Verification therefore rests on HTTPS to GitHub, the commit hash, and
the CI run, not on a signature. Anyone who can rewrite the history can rewrite what the tag points
at. I would rather write that sentence than imply a signature that does not exist.

## A modified copy is a different product

Nothing here prevents repackaging. A copy with the graders removed, the `CLEAN` prohibition deleted,
or the limitations pages dropped would still import and still print verdicts. The defences are
documentary and thin, and they are worth knowing:

- `NOTICE` and this file must travel with a redistribution, so a repackaged copy that strips them is
  out of licence.
- Every grade in this project is tied to a `falsifier` column. If a copy cannot show falsifiers, its
  claims are not this project's claims.
- `report/SECURITY_REPORT.md` names the commit it describes and is generated from it, so a copy whose
  report and code disagree is detectable by re-running the generator.

## Samples and legal posture

- **No malware samples are distributed.** The in-the-wild dataset is metadata only; the tree contains
  no firmware images. Do not open a pull request that adds one.
- **Authorised use only.** This tool reads systems and firmware. Run it on hardware you own or have
  written permission to examine; it is not a remote assessment tool and has no business on someone
  else's machine.
- **No legal advice.** The export-control treatment of cryptographic software (this implements
  AES-256-GCM) varies by jurisdiction. If you plan to redistribute in binary form, get your own
  advice; this file is not it.
- **No warranty.** Apache-2.0 §7 disclaims it, and the software is labelled a prototype on the first
  screen of the README for the same reason.
- **It does not clean anything.** Publishing this does not make anyone compliant with a firmware
  security standard, and it is not a remediation tool.

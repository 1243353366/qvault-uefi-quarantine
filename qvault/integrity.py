"""
qvault.integrity
================

Am I the build I claim to be, and is this copy the one that was published?

The uncomfortable part, first
-----------------------------
A self-check cannot detect a trojan that edited the self-check. If an attacker can
modify `qvault/integrity.py`, the modified copy answers "intact" with the same
confidence as the real one, because the answer is produced by the bytes under suspicion.
This is not a limitation to be worked around in code; it is the same evidence-direction
problem as §10.8, and the only real defences are outside this process:

1. **An out-of-band digest.** The published release states a digest. The user compares.
   A local tool can compute a digest; only something outside the tool can say what the
   digest should be.
2. **A signed build.** A manifest signed by a key the attacker does not hold, with the
   public key pinned outside the tree it describes.
3. **A hardware anchor.** The measured digest is extended into a TPM PCR and read back
   by something that is not this program.
4. **Read-only media.** A copy that cannot be written cannot be trojanised in place.

So this module does two useful things and refuses a third. It builds a manifest you can
publish, and it verifies a tree against a digest supplied from outside. It does **not**
accept a digest stored inside the tree it describes as proof of anything, because that
is a lock whose key is taped to the door: an attacker who edits the code edits the
recorded hash in the same commit.

Provenance classes
------------------
`NONE`               no external reference: every answer is unverified_self_measurement
`SELF_EMBEDDED`      digest found beside the code: refused, it proves nothing
`OUT_OF_BAND_DIGEST` digest supplied by the user or a release page: corroborated
`SIGNED_MANIFEST`    signature verified against a pinned public key: corroborated
`HARDWARE_ANCHOR`    digest extended into a TPM and read by another component: confirmed
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass

from . import findings as F
from . import limitations as L

#: Live, OS-mediated read of the running filesystem.
PLANE = getattr(L, "LIVE_STATE", "live_state")

NONE = "none"
SELF_EMBEDDED = "self_embedded"
OUT_OF_BAND_DIGEST = "out_of_band_digest"
SIGNED_MANIFEST = "signed_manifest"
HARDWARE_ANCHOR = "hardware_anchor"

PROVENANCE = (NONE, SELF_EMBEDDED, OUT_OF_BAND_DIGEST, SIGNED_MANIFEST, HARDWARE_ANCHOR)

#: Strongest claim each provenance class supports. `None` means no claim at all.
GRADE_BY_PROVENANCE = {
    NONE: None,
    SELF_EMBEDDED: None,
    OUT_OF_BAND_DIGEST: F.CORROBORATED,
    SIGNED_MANIFEST: F.CORROBORATED,
    HARDWARE_ANCHOR: F.CONFIRMED,
}

VERIFIED = "verified"
MISMATCH = "mismatch"
INCOMPARABLE = "incomparable"
UNKNOWN_PROVENANCE = "unknown_provenance"
UNVERIFIED = "unverified"

IGNORE_DIRS = {"__pycache__", ".git", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
IGNORE_SUFFIX = (".pyc", ".pyo")


class IntegrityError(RuntimeError):
    """Raised when an integrity claim would be made without the evidence for it."""


def _iter_files(root: str):
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS)
        for name in sorted(filenames):
            if name.endswith(IGNORE_SUFFIX):
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            yield full, os.path.relpath(full, root)


def build_manifest(root: str) -> dict:
    """Digest every regular file under `root`, for publication out of band."""
    files = {}
    for full, rel in _iter_files(root):
        with open(full, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        st = os.stat(full)
        files[rel.replace(os.sep, "/")] = {
            "sha256": digest,
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o777),
            "world_writable": bool(st.st_mode & 0o002),
        }
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "root": os.path.basename(os.path.abspath(root)),
        "file_count": len(files),
        "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "files": files,
    }


def verify_tree(root: str, expected_digest: str, provenance: str = NONE,
                expected_file_count: int | None = None) -> dict:
    """Compare a tree against a digest from outside it.

    `expected_digest` must come from somewhere else: a release page, a signed manifest,
    a hardware read. Passing a digest read from the same tree is `SELF_EMBEDDED` and is
    refused rather than accepted.
    """
    if provenance not in PROVENANCE:
        raise IntegrityError(f"unknown provenance {provenance!r}; known: {PROVENANCE}")

    manifest = build_manifest(root)
    gaps: list[str] = []
    grade = GRADE_BY_PROVENANCE[provenance]

    if provenance == SELF_EMBEDDED:
        raise IntegrityError(
            "a digest stored beside the code it describes proves nothing: an attacker "
            "who edits the module edits the recorded hash in the same change. Supply the "
            "digest from a release page, a signed manifest, or a hardware anchor."
        )
    # A digest only identifies a tree if it was computed over the same tree. Comparing a
    # digest built for `qvault/` against the repository root yields a mismatch that says
    # nothing about tampering, and reporting that as suspicion is how a self-check earns
    # a reputation for crying wolf. If the reference declares a file count, use it.
    if (expected_file_count is not None
            and manifest["file_count"] != expected_file_count):
        gaps.append(
            "reference_describes_a_different_tree: the digest was computed over "
            f"{expected_file_count} file(s) but this tree holds {manifest['file_count']}; "
            "a difference here cannot distinguish tampering from a wrong reference"
        )
        status = INCOMPARABLE
    elif provenance == NONE or not expected_digest:
        gaps.append(
            "unverified_self_measurement: this copy computed its own digest, so the "
            "result describes what is running, not whether it is the published build"
        )
        status = UNVERIFIED
    elif manifest["digest"] == expected_digest:
        status = VERIFIED
    else:
        status = MISMATCH
        gaps.append("digest_mismatch: this tree is not the build the digest describes")

    world_writable = sorted(rel for rel, meta in manifest["files"].items()
                            if meta["world_writable"])
    if world_writable:
        gaps.append(f"world_writable:{len(world_writable)} file(s) any local user may edit")

    return {
        "status": status,
        "digest": manifest["digest"],
        "expected": expected_digest,
        "file_count": manifest["file_count"],
        "expected_file_count": expected_file_count,
        "grade": grade if status == VERIFIED else None,
        "confidence": (F.confidence_grade(grade, tuple(gaps))
                       if status == VERIFIED and grade else F.UNKNOWN),
        "verified": status == VERIFIED,
        "gaps": gaps,
        "world_writable": world_writable,
        "statement": {
            VERIFIED: f"tree matches the externally supplied digest ({manifest['file_count']} files)",
            MISMATCH: "this tree is NOT the published build: the digest does not match",
            UNVERIFIED: (
                "digest computed but unverified: no external reference to compare against, "
                "so this is a self-measurement, not an integrity claim"
            ),
            INCOMPARABLE: (
                "not comparable: the reference digest describes a different tree, so this "
                "result says nothing either way about tampering"
            ),
        }[status],
    }


# --- impersonation --------------------------------------------------------

#: Names a trojan would use to shadow this package on the import path.
SHADOW_NAMES = ("qvault.py", "qvault", "vendor.py", "vendor")

#: Files that execute code on interpreter start, without being imported by anything.
STARTUP_HOOKS = ("sitecustomize.py", "usercustomize.py")


def impersonation_checks(root: str, sys_path=None) -> list[dict]:
    """Signals that this copy may not be the build it claims, or is being shadowed.

    Each check returns a dict; `present=True` means the condition was found, and the
    severity says what it means. None of these is proof on its own, and each one has an
    ordinary explanation (`usual_reason`), which is why this list is graded evidence and
    not a verdict.
    """
    root = os.path.abspath(root)
    checks: list[dict] = []

    def add(name, present, severity, meaning, usual):
        checks.append({
            "check": name, "present": present, "severity": severity,
            "meaning": meaning, "usual_reason": usual,
        })

    # A digest recorded inside the tree: useful for publishing, worthless as proof.
    embedded = [f for f in ("SELF_MANIFEST.json", "MANIFEST.json", "INTEGRITY.json")
                if os.path.exists(os.path.join(root, f))]
    add("embedded_self_manifest", bool(embedded), "info",
        f"self-describing manifest present ({', '.join(embedded)})",
        "normal for a release build; it must be compared out of band to mean anything")

    # Startup hooks in the package directory run code before any import of ours.
    hooks = [h for h in STARTUP_HOOKS if os.path.exists(os.path.join(root, h))]
    add("startup_hook_in_tree", bool(hooks), "high",
        f"interpreter startup hook inside the package ({', '.join(hooks)})",
        "a sitecustomize.py belongs in site-packages, not in an application directory")

    # Shadowing: something earlier on sys.path answering to our name. This is only
    # answerable if we know where we sit on the path; if the package is not on it, the
    # question becomes an explicit unknown rather than a scan of the whole interpreter.
    path = list(sys_path if sys_path is not None else sys.path)
    on_path = root in path
    here = path.index(root) if on_path else 0
    add("path_position_unknown", not on_path, "info",
        "this installation is not on sys.path, so shadowing cannot be ruled out",
        "a copy being inspected before installation, or a relocated build")
    shadows = []
    for entry in (path[:here] if on_path else []):
        if not entry:
            continue
        for name in SHADOW_NAMES:
            candidate = os.path.join(entry, name)
            if os.path.exists(candidate):
                shadows.append(candidate)
    add("import_shadowing", bool(shadows), "high",
        f"an earlier sys.path entry provides a same-named module ({', '.join(shadows[:3])})",
        "a virtualenv or editable install can do this legitimately")

    # World-writable code: anyone local can trojanise it later.
    ww = []
    for full, rel in _iter_files(root):
        st = os.stat(full)
        if st.st_mode & 0o002:
            ww.append(rel.replace(os.sep, "/"))
    add("world_writable_code", bool(ww), "high",
        f"{len(ww)} file(s) writable by any local user",
        "an unpacked archive under a permissive umask")

    # A rogue .pth file executes code at interpreter start.
    pth = []
    for entry in (path[:here] if on_path else []):
        if entry and os.path.isdir(entry):
            pth.extend(f for f in (os.path.join(entry, n) for n in os.listdir(entry))
                       if f.endswith(".pth"))
    add("pth_execution_hook", bool(pth), "medium",
        f"{len(pth)} .pth file(s) on the path before this package",
        "legitimate for some packages; arbitrary code execution for a malicious one")

    # Stray bytecode with no source is a way to ship code that review never sees.
    # A __pycache__ entry is not stray: its source lives one directory up. Getting this
    # wrong flagged every ordinary Python installation as suspicious, which is the exact
    # false positive this project measures rather than denies.
    stray = []
    for dirpath, _dirnames, filenames in os.walk(root):
        in_cache = os.path.basename(dirpath) == "__pycache__"
        for name in filenames:
            if not name.endswith(IGNORE_SUFFIX):
                continue
            stem = name.split(".cpython")[0]
            src_dir = os.path.dirname(dirpath) if in_cache else dirpath
            if not os.path.exists(os.path.join(src_dir, stem + ".py")):
                stray.append(os.path.join(dirpath, name))
    add("source_less_bytecode", bool(stray), "medium",
        f"{len(stray)} compiled module(s) with no corresponding source",
        "a build artifact left behind by a packaging step")

    return checks


def self_scan(root: str, expected_digest: str = "", provenance: str = NONE,
              sys_path=None, expected_file_count: int | None = None) -> dict:
    """Scan this installation as an artifact, not just the device it runs on.

    The result can be `suspicious` and can be `inconclusive`. It cannot be `clean`,
    because a clean result would require a trusted vantage point this process does not
    have.
    """
    integ = verify_tree(root, expected_digest, provenance=provenance,
                        expected_file_count=expected_file_count)
    checks = impersonation_checks(root, sys_path=sys_path)
    present = [c for c in checks if c["present"] and c["severity"] in ("high", "medium")]
    high = [c for c in present if c["severity"] == "high"]

    gaps = list(integ["gaps"])
    gaps.extend(f"self_check:{c['check']}" for c in present)

    if integ["status"] == MISMATCH:
        verdict = F.SUSPICIOUS_VERDICT
    elif high:
        verdict = F.SUSPICIOUS_VERDICT
    elif integ["status"] == VERIFIED and not present:
        verdict = F.NO_EVIDENCE_FOUND
    else:
        verdict = F.INCONCLUSIVE

    return {
        "verdict": verdict,
        "integrity": integ,
        "checks": checks,
        "triggered": present,
        "gaps": gaps,
        "statement": (
            f"self-scan: {integ['statement']}; {len(present)} of {len(checks)} "
            "impersonation checks triggered. "
            + ("A self-scan cannot certify the scanner: see §10.8."
               if integ["status"] != VERIFIED else "")
        ).strip(),
    }


def observation(result: dict) -> F.Observation:
    """Self-scan as a graded observation, never as an accusation."""
    gaps = tuple(result["gaps"])
    base = F.INFERRED if result["verdict"] == F.NO_EVIDENCE_FOUND else F.HYPOTHESIS
    return F.Observation(
        statement=result["statement"],
        plane=PLANE,
        grade=base,
        telemetry_gaps=gaps,
        source="qvault.integrity:self_scan",
    )


def combine(device: dict, selfcheck: dict) -> dict:
    """Device verdict, read through the question of whether the scanner is attested.

    A negative device result produced by a scanner nobody has verified is not evidence
    about the device: an unattested instrument's silence says nothing about what it did
    not look for, or was built not to see. A positive result still stands, because a
    trojanised scanner inventing findings is a different failure from missing them, but
    its grade is capped: the instrument that produced it is not reliable.
    """
    attested = bool(selfcheck.get("integrity", {}).get("verified"))
    verdict = device.get("verdict")

    if attested:
        return {
            "verdict": verdict,
            "grade_cap": None,
            "statement": (
                "scanner integrity is attested against an external reference, so the "
                "device result stands at its own grade"
            ),
            "gaps": [],
        }

    if verdict in (F.SUSPICIOUS_VERDICT, F.MALICIOUS_VERDICT):
        return {
            "verdict": verdict,
            "grade_cap": F.INFERRED,
            "statement": (
                "a finding is reported, but the scanner's own integrity is unattested, so "
                "the finding is capped at INFERRED: it is an observation from an instrument "
                "nobody has checked"
            ),
            "gaps": ["unattested_scanner: the tool that produced this result cannot show "
                     "that it is the published build"],
        }

    return {
        "verdict": F.INCONCLUSIVE,
        "grade_cap": None,
        "statement": (
            "no findings from an unattested scanner is an inconclusive result, not an "
            "absence: an instrument whose integrity is unverified cannot report silence "
            "as evidence"
        ),
        "gaps": ["unattested_scanner: absence of findings cannot be relied on until the "
                 "scanner's own integrity is verified against an external reference"],
    }

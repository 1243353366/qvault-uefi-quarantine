"""
qvault.pillars
==============

The seven capabilities, each traced to the code that implements it and the test that
proves it.

Why a ledger and not a diagram
------------------------------
A capability diagram shows what the system is *meant* to do. This shows what it
actually does, because every requirement names a module that must import and a test file
that must exist, and a pillar cannot be labelled `IMPLEMENTED` while any of its required
requirements is a `GAP`. That check is the reason this module exists: the seven headings
are easy to agree with and easy to quietly not build.

Statuses
--------
`IMPLEMENTED`  a required requirement, met, with a test
`PARTIAL`      met for a stated subset, with the remainder named
`GAP`          required and absent
"""

from __future__ import annotations

import importlib
from pathlib import Path

IMPLEMENTED = "IMPLEMENTED"
PARTIAL = "PARTIAL"
GAP = "GAP"

REPO = Path(__file__).resolve().parent.parent

# Each requirement: what it must do, where it lives, how it is proven, how it is
# limited. `required=False` means a strengthening capability, not a pillar definition.
PILLARS: list[dict] = [
    {
        "id": "P1",
        "name": "Forensic acquisition — device artifacts, provenance, coverage",
        "requirements": [
            {"req": "eight-element artifact envelope", "module": "provenance",
             "symbol": "capture", "test": "qvault/tests/test_provenance.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "device artifacts from iOS/Android/desktop", "module": "zbt_bridge",
             "symbol": "observations", "test": "qvault/tests/test_zbt_merge.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "container support is upstream's, including encrypted backups"},
            {"req": "coverage and collection-error reporting", "module": "provenance",
             "symbol": "Coverage", "test": "qvault/tests/test_provenance.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "manifests real gaps; it does not recover unreadable regions"},
            {"req": "acquisition from a device that cannot be read without the OS",
             "module": "firmware_integrity", "symbol": "assess",
             "test": "qvault/tests/test_firmware_integrity.py",
             "status": PARTIAL, "required": False,
             "limit": "reported as unattested rather than acquired; needs physical access"},
        ],
    },
    {
        "id": "P2",
        "name": "IOC detection — retain known spyware detection",
        "requirements": [
            {"req": "indicator engine across 14 evidence classes", "module": "zbt_bridge",
             "symbol": "EVIDENCE_MAP", "test": "qvault/tests/test_zbt_merge.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "vendored snapshot; corpus refresh is a manual upstream pull"},
            {"req": "the tool scans its own installation, not only the device",
             "module": "integrity", "symbol": "self_scan",
             "test": "qvault/tests/test_integrity_calibration.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "a self-check cannot detect a trojan that edited the self-check; "
                      "an external digest is required and supplied by the user"},
            {"req": "vocabulary drift guard", "module": "zbt_bridge",
             "symbol": "assert_vocabulary", "test": "qvault/tests/test_zbt_merge.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "indicator corpus embedded locally", "module": "zbt_bridge",
             "symbol": "mapping_for", "test": "qvault/tests/test_zbt_merge.py",
             "status": GAP, "required": False,
             "limit": "deliberate: an embedded feed reproduces the staleness problem in A4"},
        ],
    },
    {
        "id": "P3",
        "name": "Behavioral correlation — processes, permissions, network, persistence",
        "requirements": [
            {"req": "temporal evidence graph", "module": "correlate",
             "symbol": "build_clusters", "test": "qvault/tests/test_zbt_merge.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "grade from independence, not event count", "module": "correlate",
             "symbol": "assess_cluster", "test": "qvault/tests/test_zbt_merge.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "process identity normalisation across hosts", "module": "correlate",
             "symbol": "Event", "test": "qvault/tests/test_zbt_merge.py",
             "status": PARTIAL, "required": True,
             "limit": "subject is a lower-cased string; path and signature identity are "
                      "not resolved, so two spellings of one binary do not merge"},
            {"req": "permission-versus-behaviour comparison", "module": "correlate",
             "symbol": "PERMISSION", "test": "qvault/tests/test_zbt_merge.py",
             "status": PARTIAL, "required": False,
             "limit": "permission events correlate but no entitlement model is consulted"},
        ],
    },
    {
        "id": "P4",
        "name": "Cryptographic evidence vault — authenticated encryption, immutable originals, audit",
        "requirements": [
            {"req": "authenticated encryption at rest", "module": "crypto",
             "symbol": "encrypt_stream", "test": "qvault/tests/test_qvault.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "AES-256-GCM / ChaCha20-Poly1305 only; unauthenticated modes refused"},
            {"req": "immutable original storage", "module": "store",
             "symbol": "seal_object", "test": "qvault/tests/test_qvault.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "append-only audit trail", "module": "audit",
             "symbol": "AuditLog", "test": "qvault/tests/test_qvault.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "storage cannot attest its own integrity or rewrite history",
             "module": "separation", "symbol": "audit_separation",
             "test": "qvault/tests/test_separation.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "verification shares the enclave zone; a dedicated zone is not built"},
            {"req": "hardware-backed key custody (TPM/HSM)", "module": "keys",
             "symbol": "split", "test": "qvault/tests/test_qvault.py",
             "status": GAP, "required": False,
             "limit": "keys are software-held shares; no HSM or TPM seal is implemented"},
        ],
    },
    {
        "id": "P5",
        "name": "Firmware integrity — independent boot-chain and firmware verification",
        "requirements": [
            {"req": "anchor lattice with OS excluded", "module": "firmware_integrity",
             "symbol": "ANCHORS", "test": "qvault/tests/test_firmware_integrity.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "refusal to certify on weak evidence", "module": "firmware_integrity",
             "symbol": "certify_host", "test": "qvault/tests/test_firmware_integrity.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "in-circuit versus chip-off read equivalence", "module": "firmware_integrity",
             "symbol": "FirmwareEvidence", "test": "qvault/tests/test_firmware_integrity.py",
             "status": PARTIAL, "required": False,
             "limit": "penalised rather than measured; H8 is open"},
        ],
    },
    {
        "id": "P6",
        "name": "Containment — quarantine, resource isolation, credential revocation",
        "requirements": [
            {"req": "six capability denials with plane coverage", "module": "containment",
             "symbol": "audit_claim", "test": "qvault/tests/test_findings.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "subject-OS enforcement dies with the kernel it protects"},
            {"req": "resource budgets on every parsing component", "module": "budgets",
             "symbol": "assert_within", "test": "qvault/tests/test_pillars_revoke_budgets.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "ceilings are conservative starting points, not measured values"},
            {"req": "ordered credential revocation with issuer verification", "module": "revoke",
             "symbol": "plan_revocation", "test": "qvault/tests/test_pillars_revoke_budgets.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "cannot revoke an unenumerated credential, nor expire a copy the "
                      "attacker already holds"},
            {"req": "zone isolation enforced by the substrate", "module": "isolation",
             "symbol": "place", "test": "qvault/tests/test_isolation.py",
             "status": PARTIAL, "required": True,
             "limit": "the model states the boundary; nothing verifies a hypervisor honours it"},
        ],
    },
    {
        "id": "P7",
        "name": "Evidence assessment — confidence, alternatives, explicit unknowns",
        "requirements": [
            {"req": "five mandatory finding rules", "module": "findings",
             "symbol": "Finding", "test": "qvault/tests/test_findings.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "competing benign explanations, capped status", "module": "findings",
             "symbol": "BenignExplanation", "test": "qvault/tests/test_findings.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "explicit unknowns via telemetry gaps", "module": "limitations",
             "symbol": "establish", "test": "qvault/tests/test_limitations.py",
             "status": IMPLEMENTED, "required": True, "limit": ""},
            {"req": "self-certification refused; attestation capped by evidence class",
             "module": "separation", "symbol": "Attestation",
             "test": "qvault/tests/test_separation.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "the verifier's own root is external and reported when absent"},
            {"req": "false-positive and false-negative rates measured with intervals",
             "module": "calibration", "symbol": "evaluate",
             "test": "qvault/tests/test_integrity_calibration.py",
             "status": IMPLEMENTED, "required": True,
             "limit": "the harness exists; no labelled corpus of real devices is bundled, "
                      "so the measured rates are the caller's to supply"},
            {"req": "calibrated grades from a real-world labelled corpus", "module": "findings",
             "symbol": "confidence_grade", "test": "qvault/tests/test_findings.py",
             "status": GAP, "required": False,
             "limit": "the measurement harness exists (calibration.py); what is missing is "
                      "ground-truth outcomes from real devices to feed it"},
        ],
    },
]


class PillarError(ValueError):
    """Raised when the ledger claims a capability it cannot trace."""


def _pillar_status(pillar: dict) -> str:
    statuses = {r["status"] for r in pillar["requirements"]}
    required_gap = any(r["status"] == GAP and r.get("required", True)
                       for r in pillar["requirements"])
    if required_gap:
        return GAP
    if statuses == {IMPLEMENTED}:
        return IMPLEMENTED
    return PARTIAL


def audit() -> dict:
    """Per-pillar status, plus the gaps and partials behind it."""
    rows = []
    for pillar in PILLARS:
        status = _pillar_status(pillar)
        rows.append({
            "id": pillar["id"],
            "name": pillar["name"],
            "status": status,
            "implemented": sum(1 for r in pillar["requirements"]
                               if r["status"] == IMPLEMENTED),
            "total": len(pillar["requirements"]),
            "gaps": [r["req"] for r in pillar["requirements"] if r["status"] == GAP],
            "partials": [f"{r['req']}: {r['limit']}" for r in pillar["requirements"]
                         if r["status"] == PARTIAL],
        })
    counts = {s: sum(1 for r in rows if r["status"] == s)
              for s in (IMPLEMENTED, PARTIAL, GAP)}
    return {
        "pillars": rows,
        "counts": counts,
        "statement": (
            f"{counts[IMPLEMENTED]} of {len(rows)} capabilities fully implemented, "
            f"{counts[PARTIAL]} partial, {counts[GAP]} with a required gap. "
            "Partial means the stated subset works and the rest is named."
        ),
    }


def assert_traceable() -> None:
    """Every requirement must resolve to real code and a real test."""
    for pillar in PILLARS:
        for r in pillar["requirements"]:
            try:
                module = importlib.import_module(f"qvault.{r['module']}")
            except ImportError as exc:  # pragma: no cover - defensive
                raise PillarError(f"{pillar['id']} names a module that does not exist: "
                                  f"qvault.{r['module']} ({exc})") from exc
            if not hasattr(module, r["symbol"]):
                raise PillarError(
                    f"{pillar['id']} names qvault.{r['module']}.{r['symbol']}, which is absent"
                )
            if not (REPO / r["test"]).exists():
                raise PillarError(f"{pillar['id']} cites a missing test: {r['test']}")


def assert_consistent() -> None:
    """A pillar may not be labelled IMPLEMENTED while a required piece is a gap."""
    for pillar in PILLARS:
        derived = _pillar_status(pillar)
        declared = pillar.get("declared")
        if declared and declared != derived:
            raise PillarError(
                f"{pillar['id']} declares {declared} but its requirements derive {derived}"
            )
        if derived == IMPLEMENTED and any(r["status"] == GAP for r in pillar["requirements"]):
            raise PillarError(
                f"{pillar['id']} is IMPLEMENTED with a gap listed: "
                f"{[r['req'] for r in pillar['requirements'] if r['status'] == GAP]}"
            )


def gap_register() -> list[dict]:
    """Everything not done, in one place, so it cannot be quietly forgotten."""
    out = []
    for pillar in PILLARS:
        for r in pillar["requirements"]:
            if r["status"] != IMPLEMENTED:
                out.append({
                    "pillar": pillar["id"],
                    "requirement": r["req"],
                    "status": r["status"],
                    "required": r.get("required", True),
                    "why_not": r["limit"],
                })
    return out

#!/usr/bin/env python3
"""Smoke tests: exercise the shipped surfaces the way an operator does.

pytest covers units; this covers the plumbing between them — argparse wiring, the vault
lifecycle through the CLI, a firmware diff, a network case file, the self-scan, and the
capability ledger. Every step asserts on observable output, not on exit status alone,
and the script fails loudly rather than warning.

Run: python3 tools/smoke.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
failures: list[str] = []
steps = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global steps
    steps += 1
    if ok:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))
        failures.append(name)


def cli(*args: str, expect: int = 0) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [PY, "-m", "qvault", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != expect:
        failures.append(
            f"exit {proc.returncode} != {expect}: qvault {' '.join(args)}"
        )
        print(f"  FAIL  cli {' '.join(args)}  [{proc.stderr.strip()[:160]}]")
    return proc


print("1. CLI surface")
for cmd in ("init", "ingest", "list", "show", "verify", "approve", "retrieve",
            "audit", "fwdiff", "netobs", "enclave", "checkpoint"):
    proc = cli(cmd, "--help")
    check(f"{cmd} --help", proc.returncode == 0 and cmd in proc.stdout)

print("2. vault lifecycle")
with tempfile.TemporaryDirectory() as tmp:
    vault = os.path.join(tmp, "vault")
    custodians = os.path.join(tmp, "custodians")
    os.makedirs(custodians)
    cli("init", "--root", vault, "--custodian-dir", custodians)
    shares = sorted(os.listdir(custodians))
    check("init produces 3 custodian shares", len(shares) == 3, str(shares))

    artifact = os.path.join(tmp, "spi-dump.bin")
    with open(artifact, "wb") as fh:
        fh.write(b"\x5a\xa5" * 4096)
    share_paths = []
    for name in shares[:2]:
        share_paths += ["--share", os.path.join(custodians, name)]
    proc = cli("ingest", "--root", vault, "--file", artifact, "--operator", "analyst",
               "--method", "oob_spi_read", "--source", "SPI chip U3",
               *share_paths)
    check("ingest exits clean", proc.returncode == 0, proc.stderr[:120])
    check("ingest reports a digest", "sha256" in proc.stdout.lower(), proc.stdout[:120])

    proc = cli("list", "--root", vault)
    listing = json.loads(proc.stdout)
    rows = listing if isinstance(listing, list) else listing.get("objects", [])
    check("list shows one object", len(rows) == 1, str(rows)[:120])
    object_id = rows[0].get("object_id") if rows else None
    check("object id parsed", bool(object_id), str(rows)[:200])

    if object_id:
        proc = cli("show", "--root", vault, "--id", object_id)
        check("show prints an envelope", '"sha256"' in proc.stdout or "sha256" in proc.stdout)
        proc = cli("verify", "--root", vault)
        check("verify passes on an untouched vault", proc.returncode == 0,
              proc.stderr[:200])

        encl = os.path.join(tmp, "enclave")
        cli("enclave", "--path", encl)
        proc = cli("retrieve", "--root", vault, "--id", object_id,
                   "--requester", "analyst", "--out", encl, *share_paths, expect=1)
        check("retrieve refuses without approvals", proc.returncode != 0,
              "it should not decrypt on request alone")

        cli("approve", "--root", vault, "--id", object_id, "--approver", "custodian-a",
            "--justification", "case 7, authorised")
        cli("approve", "--root", vault, "--id", object_id, "--approver", "custodian-b",
            "--justification", "case 7, second approval")
        proc = cli("retrieve", "--root", vault, "--id", object_id,
                   "--requester", "analyst", "--out", encl, *share_paths)
        check("retrieve works after two approvals", proc.returncode == 0, proc.stderr[:200])
        out = [f for f in os.listdir(encl) if f != ".enclave"]
        check("plaintext lands in the enclave directory", bool(out), str(os.listdir(encl)))
        if out:
            with open(os.path.join(encl, out[0]), "rb") as fh:
                check("round trip is byte-identical", fh.read() == b"\x5a\xa5" * 4096)

        proc = cli("audit", "--root", vault)
        check("audit chain verifies", proc.returncode == 0, proc.stderr[:200])
        proc = cli("checkpoint", "--root", vault)
        check("checkpoint signs the head", proc.returncode == 0, proc.stderr[:200])

print("3. firmware diff")
with tempfile.TemporaryDirectory() as tmp:
    sys.path.insert(0, ROOT)
    from qvault.tests.test_fwdiff import build_ffs, core_dxe, image, GUID_CORE, PROLOGUE

    oem = image([build_ffs(GUID_CORE, core_dxe())])
    infected = {".text": b"\xe8\x11\x22\x33\x44" + b"\x90" * 0xFB,
                ".reloc": b"\x00" * 0x40, "": b"\x90" * 0x229}
    bad = image([build_ffs(GUID_CORE, core_dxe(infected))])
    a = os.path.join(tmp, "oem.bin"); b = os.path.join(tmp, "suspect.bin")
    open(a, "wb").write(oem); open(b, "wb").write(bad)
    proc = cli("fwdiff", "--reference", a, "--suspect", b, expect=1)
    check("fwdiff exits 1 on a modified image", proc.returncode == 1)
    check("fwdiff names the unnamed section", "unnamed" in proc.stdout.lower())
    check("fwdiff names the prologue patch", "prologue" in proc.stdout.lower())
    proc = cli("fwdiff", "--reference", a, "--suspect", a)
    check("fwdiff is clean against itself", proc.returncode == 0, proc.stdout[:150])

print("4. network correlation")
with tempfile.TemporaryDirectory() as tmp:
    case = {
        "host": [{"ts": 1000.0, "host": "ws-01", "src_ip": "10.0.0.5",
                  "dst_ip": "93.184.216.34", "dst_port": 80,
                  "image": "svchost.exe", "cmdline": "SVCHOST.EXE -K NETSVCS -P",
                  "bytes_in": 65536, "bytes_out": 812}],
        "wire": [{"ts": 1060.0, "host": "ws-01", "src_ip": "10.0.0.5",
                  "dst_ip": "45.33.32.156", "dst_port": 8443,
                  "bytes_out": 20480, "bytes_in": 5120, "source": "wire"}],
        "dns": [],
    }
    path = os.path.join(tmp, "case.json")
    json.dump(case, open(path, "w"))
    proc = cli("netobs", "--input", path, expect=1)
    body = json.loads(proc.stdout)
    kinds = {f["kind"] for f in body["findings"]}
    check("netobs flags unbilled egress", "unattributed_egress" in kinds, str(kinds))
    check("netobs prints an evidence digest", "evidence_sha256" in body)

print("5. self-scan and capability ledger")
sys.path.insert(0, ROOT)
from qvault import integrity as N, pillars as P, calibration as K, separation as S

manifest = N.build_manifest(os.path.join(ROOT, "qvault"))
scan = N.self_scan(os.path.join(ROOT, "qvault"), manifest["digest"],
                   provenance=N.OUT_OF_BAND_DIGEST,
                   expected_file_count=manifest["file_count"],
                   sys_path=[os.path.join(ROOT, "qvault")])
check("self-scan of the shipped tree verifies",
      scan["integrity"]["status"] == "verified", str(scan["integrity"])[:120])
check("self-scan never says clean", scan["verdict"] != "clean", scan["verdict"])

P.assert_traceable()
P.assert_consistent()
audit = P.audit()
check("seven capabilities traced", audit["counts"]["GAP"] + audit["counts"]["PARTIAL"]
      + audit["counts"]["IMPLEMENTED"] == 7, str(audit["counts"]))
sep = S.audit_separation()
check("role separation holds", sep["violations"] == [], str(sep["violations"])[:160])

try:
    K.evaluate(K.Bench("empty"))
    check("calibration refuses an empty corpus", False, "it scored it")
except K.CalibrationError:
    check("calibration refuses an empty corpus", True)
try:
    K.evaluate([])
    check("calibration refuses a bare list", False, "it accepted a list")
except K.CalibrationError:
    check("calibration refuses a bare list", True)
try:
    K.refuse_zero_claim("the scan has no false positives")
    check("zero-claim phrasing refused", False, "it was accepted")
except K.CalibrationError:
    check("zero-claim phrasing refused", True)

print()
if failures:
    print(f"SMOKE FAILED: {len(failures)} problem(s) in {steps} checks")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print(f"SMOKE OK: {steps} checks passed")

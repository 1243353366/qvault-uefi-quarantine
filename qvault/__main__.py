"""Command line interface for the quarantine vault.

    python -m qvault init      --root vault --shares 3 --threshold 2 --custodian-dir custodian
    python -m qvault ingest    --root vault --file dump.bin --operator aadi --method "SPI flash read (CHIPSEC)" --share custodian/share-1.json --share custodian/share-2.json
    python -m qvault list      --root vault
    python -m qvault show      --root vault --id <object-id>
    python -m qvault verify    --root vault
    python -m qvault approve   --root vault --id <object-id> --approver reviewer1 --justification "case 2026-11"
    python -m qvault retrieve  --root vault --id <object-id> --requester analyst --out enclave/ --share custodian/share-1.json --share custodian/share-3.json
    python -m qvault audit     --root vault
    python -m qvault checkpoint --root vault
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time

from . import store
from .store import write_once
from .audit import AuditLog
from .crypto import canonical_json
from .ingest import ingest
from .keys import new_kek, read_shares, split, write_share
from .retrieve import read_vault_config, record_approval, retrieve
from .verify import verify_vault


def _json_out(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _kek_from_shares(root: str, share_paths: list[str]) -> bytes:
    cfg = read_vault_config(root)
    shares = read_shares(share_paths)
    if len(shares) < int(cfg["threshold"]):
        raise SystemExit(
            f"quorum not met: {len(shares)} share(s) supplied, {cfg['threshold']} required"
        )
    from .retrieve import rebuild_kek

    return rebuild_kek(shares, int(cfg["threshold"]), cfg["kek_id"])


def cmd_lan(args) -> None:
    from . import lan as lan_mod

    with open(args.case, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    case = lan_mod.load_case(doc)
    assessment = lan_mod.cross_layer(
        devices=case["devices"], flows=case["flows"], auths=case["auths"],
        discovery=case["discovery"], firmware=case["firmware"],
        endpoint_findings=case["endpoint_findings"],
        provenance_gaps=case["provenance_gaps"],
    )
    plan = lan_mod.containment_plan(assessment, case["enforcement"])
    _json_out({
        "verdict": assessment["verdict"],
        "grade": assessment["grade"],
        "identity": assessment["identity"],
        "independent_layers": assessment["independent_layers"],
        "gaps": assessment["gaps"],
        "containment": {
            "steps": [s["step"] for s in plan["steps"]],
            "refused": plan["refused"],
        },
    })


def cmd_init(args) -> None:
    paths = store.VaultPaths.open(args.root)
    cfg_path = os.path.join(args.root, "vault.json")
    if os.path.exists(cfg_path):
        raise SystemExit("vault already initialised")

    kek = new_kek()
    shares = split(kek, args.threshold, args.shares)
    os.makedirs(args.custodian_dir, exist_ok=True)
    written = []
    for sh in shares:
        p = os.path.join(args.custodian_dir, f"share-{sh.index}.json")
        write_share(p, sh)
        written.append(p)

    AuditLog(paths.audit).init_signing_key(os.path.join(args.root, "audit-signing.key"))

    from hashlib import sha256

    cfg = {
        "version": 1,
        "kek_id": sha256(kek).hexdigest()[:32],
        "threshold": args.threshold,
        "shares": args.shares,
        "approvals_required": args.approvals,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    store.write_once(cfg_path, canonical_json(cfg), mode=0o400)

    AuditLog(paths.audit).append(
        "vault.initialised",
        "vault",
        {"threshold": args.threshold, "shares": args.shares, "kek_id": cfg["kek_id"]},
    )
    _json_out(
        {
            "vault": os.path.abspath(args.root),
            "kek_id": cfg["kek_id"],
            "shares_written": written,
            "warning": "Distribute these share files to separate custodians now, then "
            "delete local copies. Anyone holding the threshold can decrypt the vault.",
        }
    )


def cmd_ingest(args) -> None:
    paths = store.VaultPaths.open(args.root)
    kek = _kek_from_shares(args.root, args.share)
    env = ingest(
        paths,
        kek,
        args.file,
        operator=args.operator,
        method=args.method,
        source_label=args.source,
        notes=args.notes,
    )
    _json_out(
        {
            "object_id": env["object_id"],
            "plaintext_sha256": env["plaintext_sha256"],
            "size": env["plaintext_size"],
            "triage": env["triage"],
        }
    )


def cmd_list(args) -> None:
    paths = store.VaultPaths.open(args.root)
    rows = []
    for env in store.list_objects(paths):
        rows.append(
            {
                "object_id": env["object_id"],
                "size": env["plaintext_size"],
                "state": env["state"],
                "source": env["custody"]["source"],
                "operator": env["custody"]["operator"],
                "ingested_at": env["custody"]["ingested_at"],
                "ioc_hits": env["triage"].get("ioc_hits", []),
            }
        )
    _json_out(rows)


def cmd_show(args) -> None:
    paths = store.VaultPaths.open(args.root)
    _json_out(store.get_envelope(paths, args.id))


def cmd_verify(args) -> None:
    paths = store.VaultPaths.open(args.root)
    rep = verify_vault(paths)
    _json_out(rep.to_dict())
    sys.exit(0 if rep.ok else 1)


def cmd_approve(args) -> None:
    paths = store.VaultPaths.open(args.root)
    record_approval(paths, args.id, args.approver, justification=args.justification)
    from .retrieve import load_approvals

    _json_out({"object_id": args.id, "approvals": load_approvals(paths, args.id)})


def cmd_retrieve(args) -> None:
    paths = store.VaultPaths.open(args.root)
    cfg = read_vault_config(args.root)
    kek = _kek_from_shares(args.root, args.share)
    del kek  # rebuild_kek is done again inside retrieve() with the same shares
    from .keys import read_shares as _rs

    out = retrieve(
        paths,
        args.id,
        shares=_rs(args.share),
        threshold=int(cfg["threshold"]),
        requester=args.requester,
        out_dir=args.out,
        approvals_required=int(cfg.get("approvals_required", 2)),
        filename=args.filename,
    )
    _json_out({"decrypted_to": out, "mode": oct(os.stat(out).st_mode & 0o777)})


def cmd_audit(args) -> None:
    paths = store.VaultPaths.open(args.root)
    log = AuditLog(paths.audit)
    ok, msg = log.verify()
    _json_out({"ok": ok, "message": msg, "entries": len(log.entries())})
    sys.exit(0 if ok else 1)


def cmd_fwdiff(args) -> None:
    from .fwdiff import diff_files

    rep = diff_files(args.reference, args.suspect)
    _json_out(rep)
    sys.exit(0 if rep["severity"] == "clean" else 1)


def cmd_netobs(args) -> None:
    from .netobs import DnsEvent, FlowEvent, correlate, evaluate_rules, to_evidence
    from hashlib import sha256

    with open(args.input, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    host = [FlowEvent(**r) for r in doc.get("host", [])]
    wire = [FlowEvent(**r) for r in doc.get("wire", [])]
    dns = [DnsEvent(**r) for r in doc.get("dns", [])]

    findings = correlate(host, wire) + evaluate_rules(host + wire, dns)
    evidence = to_evidence(host + wire + dns)
    _json_out(
        {
            "findings": [f.to_dict() for f in findings],
            "counts": {
                "host": len(host),
                "wire": len(wire),
                "dns": len(dns),
                "high": sum(1 for f in findings if f.severity == "high"),
            },
            "evidence_sha256": sha256(evidence).hexdigest(),
        }
    )
    sys.exit(0 if not any(f.severity == "high" for f in findings) else 1)


def cmd_enclave(args) -> None:
    """Create an analysis enclave: the only place plaintext may be written.

    retrieve() refuses an output directory without the sentinel, which is the control
    that stops decrypted evidence landing in a shared folder. Nothing created the marked
    directory, so the documented workflow was unreachable from the CLI.
    """
    path = os.path.abspath(args.path)
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    sentinel = os.path.join(path, ".enclave")
    if not os.path.exists(sentinel):
        write_once(sentinel, b"qvault analysis enclave\n", mode=0o400)
    _json_out({
        "enclave": path,
        "sentinel": sentinel,
        "note": "plaintext may be written here and must be destroyed after analysis",
    })


def cmd_checkpoint(args) -> None:
    paths = store.VaultPaths.open(args.root)
    name = f"checkpoint-{int(time.time())}.json"
    cp = AuditLog(paths.audit).checkpoint(os.path.join(paths.checkpoints, name))
    _json_out({"checkpoint": name, **cp})


def cmd_authz(args) -> None:
    """Verify the four elements from files. Runs anywhere: it needs no vault and no host state."""
    from . import authorization as authz

    with open(args.bundle, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    with open(args.keys, "r", encoding="utf-8") as fh:
        keys = json.load(fh)
    out = authz.verify_bundle(
        bundle,
        root_public_hex=args.root,
        public_keys=keys,
        attested_executors=[x for x in args.attested.split(",") if x],
        observed_plaintext_sha256=args.plaintext_sha256,
        used_nonces=authz.NonceStore(args.nonces) if args.nonces else None,
    )
    _json_out(out)
    # A refusal is a result, not a crash: report it and exit nonzero so scripts can branch on it.
    if out["overall"] in ("REFUSED", "MALFORMED"):
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="qvault", description=__doc__)
    from . import __version__
    p.add_argument("--version", action="version", version=f"qvault {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="create a vault and split the KEK")
    i.add_argument("--root", required=True)
    i.add_argument("--shares", type=int, default=3)
    i.add_argument("--threshold", type=int, default=2)
    i.add_argument("--approvals", type=int, default=2)
    i.add_argument("--custodian-dir", required=True)
    i.set_defaults(func=cmd_init)

    g = sub.add_parser("ingest", help="encrypt and seal one file")
    g.add_argument("--root", required=True)
    g.add_argument("--file", required=True)
    g.add_argument("--operator", required=True)
    g.add_argument("--method", required=True)
    g.add_argument("--source", default="")
    g.add_argument("--notes", default="")
    g.add_argument("--share", action="append", required=True)
    g.set_defaults(func=cmd_ingest)

    ls = sub.add_parser("list", help="list sealed objects")
    ls.add_argument("--root", required=True)
    ls.set_defaults(func=cmd_list)

    sh = sub.add_parser("show", help="show one envelope")
    sh.add_argument("--root", required=True)
    sh.add_argument("--id", required=True)
    sh.set_defaults(func=cmd_show)

    v = sub.add_parser("verify", help="verify vault integrity")
    v.add_argument("--root", required=True)
    v.set_defaults(func=cmd_verify)

    a = sub.add_parser("approve", help="record one approval for retrieval")
    a.add_argument("--root", required=True)
    a.add_argument("--id", required=True)
    a.add_argument("--approver", required=True)
    a.add_argument("--justification", required=True)
    a.set_defaults(func=cmd_approve)

    r = sub.add_parser("retrieve", help="decrypt one object into an enclave")
    r.add_argument("--root", required=True)
    r.add_argument("--id", required=True)
    r.add_argument("--requester", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--filename", default=None)
    r.add_argument("--share", action="append", required=True)
    r.set_defaults(func=cmd_retrieve)

    au = sub.add_parser("audit", help="verify the audit chain")
    au.add_argument("--root", required=True)
    au.set_defaults(func=cmd_audit)

    fd = sub.add_parser(
        "fwdiff", help="diff a suspect firmware image against an OEM reference image"
    )
    fd.add_argument("--reference", required=True, help="known-good OEM image")
    fd.add_argument("--suspect", required=True, help="image under examination")
    fd.set_defaults(func=cmd_fwdiff)

    nb = sub.add_parser(
        "netobs", help="correlate network observation against host accounting"
    )
    nb.add_argument(
        "--input", required=True, help="JSON case file with host[], wire[], dns[]"
    )
    nb.set_defaults(func=cmd_netobs)

    en = sub.add_parser("enclave", help="create an analysis enclave for plaintext")
    en.add_argument("--path", required=True)
    en.set_defaults(func=cmd_enclave)

    ln = sub.add_parser("lan", help="assess a LAN case file and plan containment")
    ln.add_argument("--case", required=True)
    ln.set_defaults(func=cmd_lan)

    az = sub.add_parser("authz", help="verify a four-element authorization bundle from files alone")
    az.add_argument("bundle", help="bundle JSON: intent, approvals, policy, receipt")
    az.add_argument("--root", required=True, help="hex Ed25519 public key of the policy root")
    az.add_argument("--keys", required=True, help="JSON mapping fingerprint -> hex public key")
    az.add_argument("--plaintext-sha256", help="sha256 of the bytes you actually received")
    az.add_argument("--attested", default="", help="comma-separated executor fingerprints confirmed "
                                                   "out of band")
    az.add_argument("--nonces", help="nonce store file, to refuse replays across runs")
    az.set_defaults(func=cmd_authz)
    cp = sub.add_parser("checkpoint", help="sign the current audit head")
    cp.add_argument("--root", required=True)
    cp.set_defaults(func=cmd_checkpoint)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

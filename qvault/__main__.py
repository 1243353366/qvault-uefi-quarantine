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


def cmd_checkpoint(args) -> None:
    paths = store.VaultPaths.open(args.root)
    name = f"checkpoint-{int(time.time())}.json"
    cp = AuditLog(paths.audit).checkpoint(os.path.join(paths.checkpoints, name))
    _json_out({"checkpoint": name, **cp})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="qvault", description=__doc__)
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

    cp = sub.add_parser("checkpoint", help="sign the current audit head")
    cp.add_argument("--root", required=True)
    cp.set_defaults(func=cmd_checkpoint)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

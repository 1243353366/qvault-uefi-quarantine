"""
qvault.retrieve
===============

The only path that turns ciphertext back into bytes, and it is deliberately
awkward to use. Four independent gates, all of which must pass:

  1. **Quorum.** K of N Shamir shares must be supplied to rebuild the KEK.
  2. **Dual control.** N distinct approvers must have recorded an approval for
     this specific object, and the requester cannot be one of them
     (separation of duties).
  3. **Enclave target.** Output must land inside a directory containing the
     `.enclave` sentinel. A normal workstation directory will refuse.
  4. **Inert output.** The plaintext is written 0400, never executable, under a
     name that makes accidental execution unlikely, and every retrieval is
     appended to the audit log with the approvers and share indices used.

What this does not do: it does not make decryption safe on a hostile host. If
the analysis host is compromised, the gate checks themselves can be attacked.
That is why the enclave is specified as a physically separate, network-less
machine whose hypervisor and firmware are re-flashed between cases.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from hashlib import sha256

from . import store
from .crypto import CryptoError, StreamHeader, decrypt_stream, unwrap_key
from .keys import Share, combine


class AuthorizationError(PermissionError):
    pass


_OBJECT_ID = re.compile(r"^[0-9a-f]{64}$")
_APPROVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _validate_object_id(object_id: str) -> None:
    if not isinstance(object_id, str) or not _OBJECT_ID.fullmatch(object_id):
        raise AuthorizationError("object id must be a 64-character lowercase SHA-256 hex digest")


def _approvals_dir(paths: store.VaultPaths) -> str:
    d = os.path.join(paths.root, "approvals")
    os.makedirs(d, exist_ok=True)
    return d


def record_approval(
    paths: store.VaultPaths, object_id: str, approver: str, *, justification: str
) -> str:
    """Record one human approval for one object. Append-only per approver."""
    _validate_object_id(object_id)
    if not isinstance(approver, str) or not _APPROVER.fullmatch(approver):
        raise AuthorizationError("approver must be a safe identifier (letters, digits, . _ @ -)")
    if not isinstance(justification, str) or not justification.strip():
        raise AuthorizationError("approver and justification are required")
    d = os.path.join(_approvals_dir(paths), object_id)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{approver}.json")
    if os.path.exists(path):
        raise AuthorizationError(f"{approver} already approved this object")
    payload = {"approver": approver, "justification": justification}
    from .crypto import canonical_json
    from .store import write_once

    write_once(path, canonical_json(payload), mode=0o400)

    from .audit import AuditLog

    AuditLog(paths.audit).append(
        "object.approved", object_id, {"approver": approver, "justification": justification}
    )
    return path


def load_approvals(paths: store.VaultPaths, object_id: str) -> list[str]:
    _validate_object_id(object_id)
    d = os.path.join(_approvals_dir(paths), object_id)
    if not os.path.isdir(d):
        return []
    approvals = []
    for name in sorted(os.listdir(d)):
        if not name.endswith(".json"):
            continue
        approver = name[:-5]
        if not _APPROVER.fullmatch(approver):
            raise AuthorizationError("approval directory contains an invalid approver identity")
        try:
            with open(os.path.join(d, name), encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, ValueError) as exc:
            raise AuthorizationError(f"approval record {name!r} is unreadable") from exc
        if (not isinstance(payload, dict) or payload.get("approver") != approver
                or not isinstance(payload.get("justification"), str)
                or not payload["justification"].strip()):
            raise AuthorizationError(f"approval record {name!r} is malformed or mismatched")
        approvals.append(approver)
    return approvals


def rebuild_kek(shares: list[Share], threshold: int, kek_id: str) -> bytes:
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise AuthorizationError("share threshold must be a positive integer")
    if len(shares) < threshold:
        raise AuthorizationError(
            f"quorum not met: {len(shares)} of {threshold} required shares supplied"
        )
    kek = combine(shares)
    if sha256(kek).hexdigest()[:32] != kek_id:
        raise AuthorizationError("reconstructed KEK does not match vault key id")
    return kek


def retrieve(
    paths: store.VaultPaths,
    object_id: str,
    *,
    shares: list[Share],
    threshold: int,
    requester: str,
    out_dir: str,
    approvals_required: int = 2,
    filename: str | None = None,
) -> str:
    """Decrypt one object into the analysis enclave. Returns the output path."""
    from .audit import AuditLog

    _validate_object_id(object_id)
    if not isinstance(requester, str) or not requester.strip():
        raise AuthorizationError("requester is required")
    if isinstance(approvals_required, bool) or not isinstance(approvals_required, int) or approvals_required < 1:
        raise AuthorizationError("approvals_required must be a positive integer")
    env = store.get_envelope(paths, object_id)
    if env.get("state") != "sealed":
        raise AuthorizationError(f"object state is {env.get('state')!r}, not sealed")

    approvals = load_approvals(paths, object_id)
    distinct = [a for a in approvals if a != requester]
    if len(distinct) < approvals_required:
        raise AuthorizationError(
            f"dual control not satisfied: {len(distinct)} of {approvals_required} "
            "independent approvals (requester cannot approve)"
        )

    kek = rebuild_kek(shares, threshold, env["kek_id"])

    sentinel = os.path.join(out_dir, ".enclave")
    if not os.path.isfile(sentinel):
        raise AuthorizationError(
            "target directory is not an analysis enclave (missing .enclave sentinel)"
        )

    dek = unwrap_key(kek, env["wrapped_dek"], aad_obj=env["aad_bind"])
    header = StreamHeader.from_dict(env["header"])

    name = filename or f"{object_id[:32]}.sample"
    if (not isinstance(name, str) or not _FILENAME.fullmatch(name)
            or name in {".", ".."}):
        raise AuthorizationError("output filename must be a simple safe filename, not a path")
    out_dir = os.path.abspath(out_dir)
    if not os.path.isdir(out_dir):
        raise AuthorizationError("enclave output directory does not exist")
    out_path = os.path.join(out_dir, name)
    if os.path.lexists(out_path):
        raise AuthorizationError("refusing to overwrite an existing output file")

    fd, tmp = tempfile.mkstemp(prefix=".qvault-", suffix=".partial", dir=out_dir)
    try:
        src_path = store.object_path(paths, object_id)
        with open(src_path, "rb") as src, os.fdopen(fd, "wb") as dst:
            total = decrypt_stream(dek, src, dst, header=header, aad_obj=env["aad_bind"])
            dst.flush()
            os.fsync(dst.fileno())

        if total != env["plaintext_size"]:
            raise CryptoError("decrypted size does not match envelope")

        h = sha256()
        with open(tmp, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != env["plaintext_sha256"]:
            raise CryptoError("plaintext hash mismatch after decryption")

        os.chmod(tmp, 0o400)
        # Hard-link is atomic and cannot overwrite a pre-existing destination.
        os.link(tmp, out_path)
        try:
            AuditLog(paths.audit).append(
                "object.retrieved", object_id,
                {
                    "requester": requester,
                    "approvers": distinct[:approvals_required],
                    "share_indices": sorted(s.index for s in shares),
                    "out_dir": out_dir,
                    "filename": name,
                    "plaintext_sha256": env["plaintext_sha256"],
                },
            )
        except Exception:
            os.unlink(out_path)
            raise
        return out_path
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def read_vault_config(root: str) -> dict:
    path = os.path.join(root, "vault.json")
    if not os.path.exists(path):
        raise store.StoreError("vault is not initialised (no vault.json)")
    with open(path) as fh:
        return json.load(fh)

"""
qvault.store
============

Immutable, content-addressed object store.

Properties enforced here:

* **Write-once.** Objects are created with O_EXCL, written to a temp file,
  fsynced, then hard-linked into place. Existing objects are never rewritten.
* **Read-only after seal.** Permissions are dropped to 0400 on seal, and the
  store refuses to open an object for writing twice.
* **Content addressed.** The object id is the SHA-256 of the *ciphertext*, not
  the plaintext, so the id does not leak a hash that an adversary could use as
  a confirmation oracle ("is this the sample I think it is?").
* **Self-describing envelope.** Each object has a JSON envelope with the
  stream header, wrapped DEK, custodian metadata and the acquisition record.

Real deployments should put this same layout on WORM media (S3 Object Lock in
compliance mode, or an append-only filesystem snapshot), because a local
filesystem alone cannot stop a root-level attacker from deleting files.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from hashlib import sha256
from typing import Iterator

from . import separation as S
from .crypto import canonical_json, sha256_file


class StoreError(RuntimeError):
    pass


@dataclass
class VaultPaths:
    root: str
    objects: str
    envelopes: str
    audit: str
    checkpoints: str

    @classmethod
    def open(cls, root: str) -> "VaultPaths":
        p = cls(
            root=root,
            objects=os.path.join(root, "objects"),
            envelopes=os.path.join(root, "envelopes"),
            audit=os.path.join(root, "audit.log"),
            checkpoints=os.path.join(root, "checkpoints"),
        )
        for d in (p.objects, p.envelopes, p.checkpoints):
            os.makedirs(d, exist_ok=True)
        return p


def write_once(path: str, data: bytes, mode: int = 0o400) -> None:
    """Create `path` exactly once. Raises if it already exists."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def seal_object(paths: VaultPaths, tmp_path: str, object_id: str) -> str:
    """Move a freshly written ciphertext into the immutable object namespace."""
    final = os.path.join(paths.objects, f"{object_id}.qv")
    if os.path.exists(final):
        raise StoreError(f"object {object_id[:16]}... already sealed")
    os.chmod(tmp_path, 0o400)
    # os.link refuses to overwrite; unlink the temp afterwards.
    os.link(tmp_path, final)
    os.unlink(tmp_path)
    return final


def put_envelope(paths: VaultPaths, object_id: str, envelope: dict) -> str:
    path = os.path.join(paths.envelopes, f"{object_id}.json")
    write_once(path, canonical_json(envelope), mode=0o400)
    return path


def get_envelope(paths: VaultPaths, object_id: str) -> dict:
    path = os.path.join(paths.envelopes, f"{object_id}.json")
    if not os.path.exists(path):
        raise StoreError(f"object {object_id} not available")
    with open(path) as fh:
        return json.load(fh)


def list_objects(paths: VaultPaths) -> Iterator[dict]:
    for name in sorted(os.listdir(paths.envelopes)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(paths.envelopes, name)) as fh:
            env = json.load(fh)
        yield env


def object_path(paths: VaultPaths, object_id: str) -> str:
    p = os.path.join(paths.objects, f"{object_id}.qv")
    if not os.path.exists(p):
        raise StoreError(f"object {object_id} not available")
    return p


def merkle_root(leaves: list[str]) -> str:
    """Binary Merkle root over object ids (hex strings)."""
    if not leaves:
        return "0" * 64
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256(a + b).digest() for a, b in zip(level[0::2], level[1::2])]
    return level[0].hex()


def inventory_digest(paths: VaultPaths) -> tuple[int, str]:
    """(count, merkle_root) over every sealed object, recomputed from disk."""
    ids = []
    for env in list_objects(paths):
        oid = env["object_id"]
        p = object_path(paths, oid)
        actual = sha256_file(p)
        if actual != env["ciphertext_sha256"]:
            raise StoreError(f"object {oid} ciphertext hash mismatch (corruption or tamper)")
        ids.append(oid)
    return len(ids), merkle_root(sorted(ids))


# --------------------------------------------------------------------------------------
# Storage durability
#
# A filesystem cannot tell the code that it is append-only, so the class is declared and
# the declaration is what the claim rests on. Detection is deliberately not attempted:
# guessing "this looks like object-lock" would be a claim with no evidence behind it.
# --------------------------------------------------------------------------------------

STORAGE_MARKER = "storage.json"
NOT_WORM = S.NOT_WORM
STORAGE_CLASSES = S.STORAGE_CLASSES


def storage_class(paths: VaultPaths) -> str:
    """The declared durability class of this vault, defaulting to not_worm.

    Declaration order: `<root>/storage.json` {"class": ...}, then QVAULT_STORAGE_CLASS.
    An unrecognised value is refused rather than treated as durable.
    """
    marker = os.path.join(paths.root, STORAGE_MARKER)
    declared = None
    if os.path.exists(marker):
        try:
            with open(marker, encoding="utf-8") as fh:
                declared = json.load(fh).get("class")
        except (OSError, ValueError) as exc:
            raise StoreError(f"storage declaration is unreadable: {exc}") from exc
    if declared is None:
        declared = os.environ.get("QVAULT_STORAGE_CLASS")
    if declared is None:
        return NOT_WORM
    if declared not in STORAGE_CLASSES:
        raise StoreError(f"unknown storage class {declared!r}; known: {STORAGE_CLASSES}")
    return declared


def declare_storage(paths: VaultPaths, storage: str) -> str:
    """Record the vault's durability class. Refuses values it cannot honour."""
    if storage not in STORAGE_CLASSES:
        raise StoreError(f"unknown storage class {storage!r}; known: {STORAGE_CLASSES}")
    write_once(os.path.join(paths.root, STORAGE_MARKER),
               json.dumps({"class": storage}, sort_keys=True).encode(), mode=0o444)
    return storage


def custody_summary(paths: VaultPaths) -> dict:
    """Whether an append-only claim is supported here, and why not when it is not."""
    storage = storage_class(paths)
    try:
        claim = S.assert_custody_claim(storage)
        return {"storage_class": storage, "claim_supported": True,
                "claim": claim["claim"]}
    except S.CustodyClaimError as exc:
        return {"storage_class": storage, "claim_supported": False, "reason": str(exc)}


def assert_custody(paths: VaultPaths, claim: str = "append_only_history") -> dict:
    return S.assert_custody_claim(storage_class(paths), claim)

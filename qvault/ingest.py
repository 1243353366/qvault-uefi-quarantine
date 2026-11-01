"""
qvault.ingest
=============

The ingestion path: hash, encrypt, seal, classify, record.

Ordering matters and is deliberate:

  1. Open the source read-only; get its size from stat.
  2. Generate a fresh 256-bit DEK for this object alone.
  3. Stream: read 64 KiB -> SHA-256 -> AES-256-GCM encrypt -> write.
     The plaintext on the ingestion host is only ever a 64 KiB window in RAM.
     Nothing plaintext is written to disk.
  4. Seal the ciphertext (fsync, 0400, hard-link into the immutable namespace).
  5. Classify a bounded window of the *source* afterwards. Classification
     happens last so a parser bug cannot damage evidence that is already
     preserved, and the triage code never decompresses or loads anything.
  6. Append the custody record to the hash-chained audit log.

Honest limitation: step 3 cannot stop code that already executes on the
ingestion host. That is an architectural problem (see the report's failure
analysis), not a cryptographic one. The mitigation is a disposable acquisition
appliance that boots from read-only media and has no writable plaintext path.
"""

from __future__ import annotations

import os
import platform
import secrets
import time
from hashlib import sha256

from . import store
from .crypto import CryptoError, StreamHeader, canonical_json, encrypt_stream, wrap_key
from .keys import KEY_LEN
from .triage import triage_bytes

TOOL = "qvault/1.0"


class _HashingWriter:
    """Write-through wrapper that hashes exactly the bytes that reach the file."""

    def __init__(self, fh):
        self._fh = fh
        self._h = sha256()

    def write(self, b: bytes) -> int:
        self._h.update(b)
        return self._fh.write(b)

    def hexdigest(self) -> str:
        return self._h.hexdigest()


def _hash_stream(fh, size: int, block: int = 1 << 20) -> str:
    fh.seek(0)
    h = sha256()
    remaining = size
    while remaining > 0:
        chunk = fh.read(min(block, remaining))
        if not chunk:
            break
        h.update(chunk)
        remaining -= len(chunk)
    fh.seek(0)
    return h.hexdigest()


def ingest(
    paths: store.VaultPaths,
    kek: bytes,
    source_path: str,
    *,
    operator: str,
    method: str,
    source_label: str = "",
    notes: str = "",
    ioc_tokens: list[str] | None = None,
) -> dict:
    """Encrypt-and-seal one file. Returns the envelope that was written."""
    from .audit import AuditLog

    if len(kek) != KEY_LEN:
        raise CryptoError("KEK must be 32 bytes")

    size = os.stat(source_path).st_size
    envelope_id = secrets.token_hex(16)
    dek = secrets.token_bytes(KEY_LEN)

    tmp_path = os.path.join(paths.objects, f".incoming-{envelope_id}")
    aad_bind = {
        "envelope_id": envelope_id,
        "plaintext_size": size,
        "source_label": source_label or os.path.basename(source_path),
    }

    src = open(source_path, "rb")
    try:
        plain_sha = _hash_stream(src, size)
        with open(tmp_path, "wb") as dst:
            hw = _HashingWriter(dst)
            header: StreamHeader = encrypt_stream(
                dek, src, hw, plaintext_size=size, aad_obj=aad_bind
            )
            dst.flush()
            os.fsync(dst.fileno())
            cipher_sha = hw.hexdigest()
    finally:
        src.close()

    # Bounded, inert classification of the source (not the ciphertext).
    with open(source_path, "rb") as fh:
        head = fh.read(4 * 1024 * 1024)
    triage = triage_bytes(head, ioc_tokens=ioc_tokens)

    object_id = cipher_sha
    wrapped = wrap_key(kek, dek, aad_obj=aad_bind)
    del dek

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    envelope = {
        "envelope_version": 1,
        "object_id": object_id,
        "envelope_id": envelope_id,
        "ciphertext_sha256": cipher_sha,
        "plaintext_sha256": plain_sha,
        "plaintext_size": size,
        "header": header.to_dict(),
        "aad_bind": aad_bind,
        "wrapped_dek": wrapped,
        "kek_id": sha256(kek).hexdigest()[:32],
        "state": "sealed",
        "custody": {
            "operator": operator,
            "method": method,
            "source": source_label or os.path.basename(source_path),
            "notes": notes,
            "ingested_at": now,
            "ingest_host": platform.node(),
            "tool": TOOL,
        },
        "triage": triage.to_dict(),
        "history": [{"event": "ingested", "ts": now, "actor": operator}],
    }

    store.seal_object(paths, tmp_path, object_id)
    store.put_envelope(paths, object_id, envelope)

    AuditLog(paths.audit).append(
        "object.ingested",
        object_id,
        {
            "envelope_sha256": sha256(canonical_json(envelope)).hexdigest(),
            "ciphertext_sha256": cipher_sha,
            "plaintext_sha256": plain_sha,
            "size": size,
            "operator": operator,
            "method": method,
            "triage": triage.to_dict(),
        },
    )
    return envelope

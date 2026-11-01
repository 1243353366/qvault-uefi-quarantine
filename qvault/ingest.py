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
        written = self._fh.write(b)
        if written != len(b):
            raise OSError("short ciphertext write")
        self._h.update(b)
        return written

    def hexdigest(self) -> str:
        return self._h.hexdigest()


class _HashingReader:
    """Hash and retain a bounded prefix of the exact bytes encrypted."""

    def __init__(self, fh, prefix_limit: int = 4 * 1024 * 1024):
        self._fh = fh
        self._h = sha256()
        self._count = 0
        self._prefix_limit = prefix_limit
        self._prefix = bytearray()

    def read(self, size: int = -1) -> bytes:
        block = self._fh.read(size)
        self._h.update(block)
        self._count += len(block)
        remaining = self._prefix_limit - len(self._prefix)
        if remaining > 0:
            self._prefix.extend(block[:remaining])
        return block

    def hexdigest(self) -> str:
        return self._h.hexdigest()

    @property
    def bytes_read(self) -> int:
        return self._count

    @property
    def prefix(self) -> bytes:
        return bytes(self._prefix)


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
        if os.fstat(src.fileno()).st_size != size:
            raise CryptoError("source size changed before acquisition")
        reader = _HashingReader(src)
        with open(tmp_path, "xb") as dst:
            hw = _HashingWriter(dst)
            header: StreamHeader = encrypt_stream(
                dek, reader, hw, plaintext_size=size, aad_obj=aad_bind
            )
            if reader.bytes_read != size or reader.read(1):
                raise CryptoError("source size changed during acquisition")
            dst.flush()
            os.fsync(dst.fileno())
            cipher_sha = hw.hexdigest()
            plain_sha = reader.hexdigest()
            triage = triage_bytes(reader.prefix, ioc_tokens=ioc_tokens)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise
    finally:
        src.close()

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

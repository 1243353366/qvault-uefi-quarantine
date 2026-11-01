"""
qvault.crypto
=============

Streaming authenticated encryption for the quarantine vault.

Design goals (all chosen for *evidence preservation*, not for speed):

1. Encrypt as we read. Bytes are authenticated-encrypted in 64 KiB chunks
   during ingestion, so a complete plaintext copy never has to exist on the
   ingestion host's filesystem.
2. Every byte is authenticated. AES-256-GCM gives confidentiality *and*
   integrity. A single flipped bit anywhere makes retrieval fail loudly
   instead of silently handing a researcher corrupted evidence.
3. Binding to metadata. The whole chunk stream is bound to the canonical
   header (AAD), so an attacker cannot swap the ciphertext of one sample
   for another, or downgrade the chunk size, without detection.

The construction is the same idea as the "STREAM" construction used by
age (age-encryption.org/v1): a per-object data key, a chunk counter nonce,
and a final-chunk flag so truncation is detectable.

Nonce layout (12 bytes, the size GCM requires):

    counter (11 bytes, big endian) || final_flag (1 byte: 0x00 or 0x01)

This is safe because every object gets a fresh 256-bit data encryption key
(DEK) that is never reused. With a unique key per object, a zero-based
counter cannot collide across objects.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from hashlib import sha256
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 64 * 1024
TAG_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
SUITE = "QV1-AES256GCM-STREAM-CHUNKED"


class CryptoError(RuntimeError):
    """Raised when authenticated decryption fails or parameters are invalid."""


def canonical_json(obj: dict) -> bytes:
    """Deterministic JSON bytes, used as AAD and for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _nonce(counter: int, final: bool) -> bytes:
    if counter < 0 or counter >= 1 << 88:
        raise CryptoError("chunk counter out of range")
    return counter.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


@dataclass(frozen=True)
class StreamHeader:
    """Everything a later reader needs, except the key."""

    suite: str
    chunk_size: int
    n_chunks: int
    plaintext_size: int

    def to_dict(self) -> dict:
        return {
            "suite": self.suite,
            "chunk_size": self.chunk_size,
            "n_chunks": self.n_chunks,
            "plaintext_size": self.plaintext_size,
        }

    def __post_init__(self) -> None:
        # Validate before a hostile header can drive a huge loop or invalid nonce.
        if self.suite != SUITE:
            raise CryptoError(f"unsupported suite: {self.suite!r}")
        if (isinstance(self.chunk_size, bool) or not isinstance(self.chunk_size, int)
                or self.chunk_size != CHUNK_SIZE):
            raise CryptoError("refusing non-standard chunk size")
        if isinstance(self.plaintext_size, bool) or not isinstance(self.plaintext_size, int):
            raise CryptoError("plaintext_size must be an integer")
        if self.plaintext_size < 0:
            raise CryptoError("plaintext_size cannot be negative")
        if isinstance(self.n_chunks, bool) or not isinstance(self.n_chunks, int):
            raise CryptoError("n_chunks must be an integer")
        expected = max(1, (self.plaintext_size + CHUNK_SIZE - 1) // CHUNK_SIZE)
        if self.n_chunks != expected or self.n_chunks >= 1 << 88:
            raise CryptoError("header has an invalid chunk count")

    @classmethod
    def from_dict(cls, d: dict) -> "StreamHeader":
        if not isinstance(d, dict):
            raise CryptoError("stream header must be an object")
        if d.get("suite") != SUITE:
            raise CryptoError(f"unsupported suite: {d.get('suite')!r}")
        try:
            return cls(
                suite=d["suite"],
                chunk_size=d["chunk_size"],
                n_chunks=d["n_chunks"],
                plaintext_size=d["plaintext_size"],
            )
        except (KeyError, TypeError) as exc:
            raise CryptoError("stream header is incomplete or malformed") from exc


def iter_chunks(fh: BinaryIO, size: int) -> Iterator[bytes]:
    """Yield the exact chunks we will encrypt, so sizing and encryption agree."""
    remaining = size
    while remaining > 0:
        block = fh.read(min(CHUNK_SIZE, remaining))
        if not block:
            raise CryptoError("unexpected end of input while chunking")
        remaining -= len(block)
        yield block


def encrypt_stream(
    key: bytes,
    src: BinaryIO,
    dst: BinaryIO,
    *,
    plaintext_size: int,
    aad_obj: dict,
) -> StreamHeader:
    """Encrypt `src` into `dst`, chunk by chunk, and return the header.

    `aad_obj` is bound to every chunk. Callers pass the object identity and
    a hash of the custody metadata so ciphertext cannot be relabelled.
    """
    if len(key) != KEY_LEN:
        raise CryptoError("data encryption key must be 32 bytes")

    n_chunks = max(1, -(-plaintext_size // CHUNK_SIZE)) if plaintext_size else 1
    header = StreamHeader(SUITE, CHUNK_SIZE, n_chunks, plaintext_size)
    aad = canonical_json({"header": header.to_dict(), "bind": aad_obj})

    aead = AESGCM(key)
    written = 0
    idx = 0
    for block in iter_chunks(src, plaintext_size):
        final = idx == n_chunks - 1
        ct = aead.encrypt(_nonce(idx, final), block, aad)
        dst.write(ct)
        written += len(block)
        idx += 1

    if plaintext_size == 0:
        # Encrypt one empty chunk so an empty object still has a valid tag.
        ct = aead.encrypt(_nonce(0, True), b"", aad)
        dst.write(ct)

    if written != plaintext_size:
        raise CryptoError("size mismatch during encryption")
    return header


def decrypt_stream(
    key: bytes,
    src: BinaryIO,
    dst: BinaryIO,
    *,
    header: StreamHeader,
    aad_obj: dict,
) -> int:
    """Decrypt and authenticate. Raises CryptoError on any tampering.

    Returns the number of plaintext bytes written.
    """
    if len(key) != KEY_LEN:
        raise CryptoError("data encryption key must be 32 bytes")
    # Also validate directly-constructed headers, not only deserialized ones.
    StreamHeader.from_dict(header.to_dict())

    aad = canonical_json({"header": header.to_dict(), "bind": aad_obj})
    aead = AESGCM(key)

    total = 0
    for idx in range(header.n_chunks):
        final = idx == header.n_chunks - 1
        want = header.chunk_size if not final else header.plaintext_size - total
        if final and header.plaintext_size == 0:
            want = 0
        if want < 0 or want > header.chunk_size:
            raise CryptoError("header describes an impossible plaintext size")
        blob = src.read(want + TAG_LEN)
        if len(blob) != want + TAG_LEN:
            raise CryptoError("ciphertext truncated")
        try:
            pt = aead.decrypt(_nonce(idx, final), blob, aad)
        except InvalidTag as exc:  # noqa: PERF203 - explicit failure path
            raise CryptoError(
                f"authentication failed at chunk {idx}: ciphertext or metadata altered"
            ) from exc
        dst.write(pt)
        total += len(pt)

    if total != header.plaintext_size:
        raise CryptoError("plaintext size mismatch after decryption")
    if src.read(1):
        raise CryptoError("trailing bytes after final chunk (truncation attack?)")
    return total


def wrap_key(kek: bytes, dek: bytes, *, aad_obj: dict) -> dict:
    """Envelope-encrypt a DEK under a key-encryption key (AES-256-GCM)."""
    if len(kek) != KEY_LEN:
        raise CryptoError("KEK must be 32 bytes")
    nonce = os.urandom(NONCE_LEN)
    aad = canonical_json({"purpose": "dek-wrap", "bind": aad_obj})
    ct = AESGCM(kek).encrypt(nonce, dek, aad)
    return {"nonce": nonce.hex(), "wrapped_dek": ct.hex(), "alg": "AES256GCM-KW"}


def unwrap_key(kek: bytes, wrapped: dict, *, aad_obj: dict) -> bytes:
    aad = canonical_json({"purpose": "dek-wrap", "bind": aad_obj})
    try:
        dek = AESGCM(kek).decrypt(
            bytes.fromhex(wrapped["nonce"]), bytes.fromhex(wrapped["wrapped_dek"]), aad
        )
    except InvalidTag as exc:
        raise CryptoError("DEK unwrap failed: wrong KEK quorum or altered envelope") from exc
    if len(dek) != KEY_LEN:
        raise CryptoError("unwrapped DEK has wrong length")
    return dek


def sha256_file(path: str, block: int = 1024 * 1024) -> str:
    h = sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(block), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()

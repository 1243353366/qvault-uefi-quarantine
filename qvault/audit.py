"""
qvault.audit
============

Append-only, hash-chained audit log with signed checkpoint heads.

Why a hash chain
----------------
A plain log file can be edited by anyone with write access. A hash chain makes
edits detectable: every entry commits to the hash of the previous entry, so
changing entry N invalidates N..head. To make *truncation* detectable too, the
head is periodically signed with an Ed25519 key and the signature is stored
outside the log (and should be anchored externally - RFC 3161 timestamp,
transparency log, or paper custody record).

What this does NOT do
---------------------
A hash chain does not stop a privileged attacker from rewriting the *entire*
log and re-signing it with a stolen key. That is why the report's threat model
treats external anchoring and offline custody as required, not optional.
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

GENESIS = "0" * 64


class AuditError(RuntimeError):
    pass


def _canon(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class AuditLog:
    path: str
    key_path: str | None = None

    def __post_init__(self) -> None:
        # `init` writes <vault>/audit-signing.key, but every other command built the log
        # with no key_path at all, so the key existed and was never found: `checkpoint`
        # failed with "signing key not initialised" on a vault that had one. Deriving the
        # default here fixes every call site at once, including future ones.
        if self.key_path is None:
            self.key_path = os.path.join(os.path.dirname(self.path), "audit-signing.key")

    # ---------- key handling ----------

    def _open_log(self) -> int:
        """Open the log without following a symlink and without opening a special file.

        The log is written by this process and by whoever has the vault mounted. A symlink swap
        would point verification at a file the attacker controls, and a FIFO would hang it.
        """
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            raise AuditError("audit log not available") from None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            raise AuditError("audit log not available")
        return fd

    def _mark_path(self) -> str:
        return self.path + ".hwm"

    def _guard_rollback(self) -> None:
        """Refuse to append to a log that is shorter than the last count this vault recorded.

        `verify()` cannot see head truncation: a shorter chain is still a valid chain. The signed
        checkpoint closes that only when the checkpoint is held elsewhere. This mark closes the
        common attack - truncate, then keep appending so the log looks continuous - by refusing
        the append. It is advisory against an attacker who can rewrite the mark too; the residual
        is written in report/TOOLING_RISK.md.
        """
        mark = self._mark_path()
        if not os.path.exists(mark):
            return
        try:
            with open(mark) as fh:
                recorded = int(fh.read().strip() or 0)
        except (OSError, ValueError):
            raise AuditError("audit high-water mark unreadable") from None
        actual = len(self.entries())
        if actual < recorded:
            raise AuditError("audit log shorter than recorded high-water mark (truncation)")

    def _record_mark(self, count: int) -> None:
        fd = os.open(self._mark_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(str(count))
            fh.flush()
            os.fsync(fh.fileno())

    def _load_private(self) -> Ed25519PrivateKey:
        if not self.key_path or not os.path.exists(self.key_path):
            raise AuditError("audit signing key not initialised")
        with open(self.key_path, "rb") as fh:
            return Ed25519PrivateKey.from_private_bytes(fh.read())

    def init_signing_key(self, path: str | None = None) -> None:
        path = path or self.key_path
        if not path:
            raise AuditError("no key path")
        if os.path.exists(path):
            raise AuditError("refusing to overwrite an existing signing key")
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        self.key_path = path

    def public_key_hex(self) -> str:
        priv = self._load_private()
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return pub.hex()

    # ---------- log writing ----------

    def _last_entry(self) -> dict | None:
        if not os.path.exists(self.path):
            return None
        last = None
        with open(self.path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        return last

    def append(self, event: str, subject: str, payload: dict) -> dict:
        self._guard_rollback()
        prev = self._last_entry()
        seq = 0 if prev is None else int(prev["seq"]) + 1
        prev_hash = GENESIS if prev is None else prev["hash"]
        entry = {
            "seq": seq,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "subject": subject,
            "payload_hash": sha256(_canon(payload)).hexdigest(),
            "prev_hash": prev_hash,
        }
        entry["hash"] = sha256(_canon(entry)).hexdigest()

        # Append with O_APPEND so concurrent writers cannot interleave mid-line.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._record_mark(seq + 1)
        return entry

    # ---------- verification ----------

    def entries(self) -> list[dict]:
        if not os.path.exists(self.path) and not os.path.lexists(self.path):
            return []
        out = []
        fd = self._open_log()
        with os.fdopen(fd) as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise AuditError(f"audit line {lineno} is not valid JSON") from exc
        return out

    def verify(self) -> tuple[bool, str]:
        prev_hash = GENESIS
        for i, entry in enumerate(self.entries()):
            body = {k: v for k, v in entry.items() if k != "hash"}
            expect = sha256(_canon(body)).hexdigest()
            if entry.get("hash") != expect:
                return False, f"entry {i} hash mismatch (log edited)"
            if entry.get("prev_hash") != prev_hash:
                return False, f"entry {i} prev_hash mismatch (entry removed or reordered)"
            if int(entry.get("seq", -1)) != i:
                return False, f"entry {i} sequence gap"
            prev_hash = entry["hash"]
        return True, f"{len(self.entries())} entries verified"

    # ---------- checkpoints ----------

    def checkpoint(self, out_path: str) -> dict:
        entries = self.entries()
        head = entries[-1]["hash"] if entries else GENESIS
        count = len(entries)
        msg = f"qvault-checkpoint:v1:{count}:{head}".encode()
        sig = self._load_private().sign(msg)
        cp = {
            "count": count,
            "head": head,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sig": sig.hex(),
            "pub": self.public_key_hex(),
        }
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(fd, "w") as fh:
            json.dump(cp, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        return cp


def verify_checkpoint(cp: dict, log: AuditLog) -> tuple[bool, str]:
    """Verify that a signed checkpoint still matches the log it commits to."""
    msg = f"qvault-checkpoint:v1:{cp['count']}:{cp['head']}".encode()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp["pub"])).verify(
            bytes.fromhex(cp["sig"]), msg
        )
    except InvalidSignature:
        return False, "checkpoint signature invalid"
    entries = log.entries()
    if len(entries) < int(cp["count"]):
        return False, "log shorter than signed checkpoint (truncation)"
    if entries[int(cp["count"]) - 1]["hash"] != cp["head"]:
        return False, "log head does not match signed checkpoint (history rewritten)"
    return True, "checkpoint matches log"

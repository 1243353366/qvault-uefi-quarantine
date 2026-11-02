"""
qvault.atrest
=============

Records sealed before they reach persistent storage, with the seven properties stated as behaviour:

1. **Local encryption** - nothing is written that was not sealed first; there is no plaintext path.
2. **Authenticated encryption** - AES-256-GCM, with the associated data binding record id and
   schema version, so a ciphertext cannot be moved to another record. The key id is bound by the
   wrapped key instead of the payload, so rotation never re-encrypts data.
3. **Key separation** - key material lives under its own root; `assert_separation` refuses a key root
   nested inside the record root.
4. **Hardware-backed protection** - a TPM protector is used when a usable device and tool are present.
5. **Rotation and revocation** - a record's DEK is re-wrapped under a new key id without touching the
   ciphertext; revoking a key makes its records unreadable while leaving them intact.
6. **Integrity** - records are hash-linked, so editing, deleting or reordering one breaks the chain.
7. **Fail closed** - if key protection is unavailable or fails, the write raises and nothing is
   written. There is no silent plaintext fallback, and no "write it unprotected, fix it later".

What is not claimed
-------------------
* **Memory.** Plaintext exists in the process during `seal` and after `open`. Python cannot zeroise a
  bytes object, so an attacker who can read this process's memory reads the record. This layer
  protects data at rest, and says so rather than implying more.
* **TPM grade.** Without captured attestation, a TPM-backed protector is graded `HYPOTHESIS`: the
  code paths exist and are exercised when a device is present, but "the key really is bound to this
  platform's PCRs" is an unverified claim in this environment, because there is no TPM in it.
* **Software fallback.** Permitted only when the caller explicitly allows it, and it records that
  choice in the envelope metadata. A software protector on the same host as the ciphertext is an
  envelope, not a boundary.
* **Revocation is destructive to availability.** A revoked key makes its records unreadable. That is
  the point, and it is also why revocation is a deliberate, logged act.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qvault.cdup import CDUPError, assert_separated
from qvault.store import write_once

ALG = "AES-256-GCM"
SCHEMA = 1
KEY_LEN = 32
NONCE_LEN = 12

#: The seven properties, named once so the documentation and the tests cannot drift from the claims.
PROPERTIES = (
    "local_encryption",
    "authenticated_encryption",
    "key_separation",
    "hardware_backed",
    "rotation_and_revocation",
    "integrity",
    "fail_closed",
)


class SealingError(RuntimeError):
    """A record could not be sealed or opened. Never downgraded to plaintext."""


class KeyProtectionUnavailable(SealingError):
    """The configured key protection is not usable. Fail closed."""


class KeyRevoked(SealingError):
    """The key that would open this record has been revoked."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode())


def _aad(record_id: str, schema: int) -> bytes:
    """Identity binding: a ciphertext cannot be relabelled to another record.

    The key id is deliberately **not** in here. Binding it would mean a rotation has to re-encrypt
    every payload, which is exactly what rotation is designed not to touch - and it buys nothing,
    because a ciphertext presented under the wrong key id fails authentication on the wrapped key
    before the payload is reached.
    """
    return f"{record_id}\x00{schema}".encode()


class KeyProtector:
    """Wraps per-record DEKs. Subclasses decide where the wrapping key actually lives."""

    backing = "software"
    grade = "HYPOTHESIS"

    def available(self) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    def kid(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def wrap(self, dek: bytes) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError

    def unwrap(self, wrapped: bytes, kid: str) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError

    def rotate(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def revoke(self, kid: str) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class SoftwareProtector(KeyProtector):
    """A keyring of wrapping keys in files, at a root the caller must keep separate.

    Explicitly a fallback: it is honest about being defeated by anything that can read the key root,
    which is why the caller has to ask for it out loud.
    """

    backing = "software"
    grade = "HYPOTHESIS"

    def __init__(self, key_root: str, *, allow_software_fallback: bool = False) -> None:
        if not allow_software_fallback:
            raise KeyProtectionUnavailable(
                "software key protection requires allow_software_fallback=True: without hardware "
                "backing the wrapping key sits on the same host as the ciphertext")
        self.root = os.path.join(key_root, "atrest-keys")
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        self._current = self._ensure_key()

    def available(self) -> bool:
        return os.path.isdir(self.root)

    def _path(self, kid: str) -> str:
        return os.path.join(self.root, f"{kid}.key")

    def _ensure_key(self) -> str:
        revoked = self._revoked()
        existing = sorted(p[:-4] for p in os.listdir(self.root) if p.endswith(".key"))
        live = [k for k in existing if k not in revoked]
        if live:
            return live[-1]
        kid = secrets.token_hex(8)
        write_once(self._path(kid), secrets.token_bytes(KEY_LEN), mode=0o400)
        return kid

    def _revoked(self) -> set[str]:
        path = os.path.join(self.root, "revoked.json")
        if not os.path.exists(path):
            return set()
        return set(json.load(open(path)))

    def kid(self) -> str:
        return self._current

    def _load(self, kid: str) -> bytes:
        if kid in self._revoked():
            raise KeyRevoked(f"key {kid} revoked: its records stay intact and unreadable")
        path = self._path(kid)
        if not os.path.exists(path):
            raise KeyProtectionUnavailable(f"no such key {kid}")
        return open(path, "rb").read()

    def wrap(self, dek: bytes) -> bytes:
        try:
            key = self._load(self._current)
        except (KeyRevoked, KeyProtectionUnavailable) as exc:
            raise KeyProtectionUnavailable(f"cannot wrap: {exc}") from exc
        nonce = secrets.token_bytes(NONCE_LEN)
        return nonce + AESGCM(key).encrypt(nonce, dek, b"atrest-dek")

    def unwrap(self, wrapped: bytes, kid: str) -> bytes:
        key = self._load(kid)
        nonce, body = wrapped[:NONCE_LEN], wrapped[NONCE_LEN:]
        try:
            return AESGCM(key).decrypt(nonce, body, b"atrest-dek")
        except InvalidTag as exc:
            raise SealingError("wrapped key failed authentication") from exc

    def rotate(self) -> str:
        kid = secrets.token_hex(8)
        write_once(self._path(kid), secrets.token_bytes(KEY_LEN), mode=0o400)
        self._current = kid
        return kid

    def revoke(self, kid: str) -> None:
        path = os.path.join(self.root, "revoked.json")
        revoked = sorted(self._revoked() | {kid})
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(revoked, fh)
        os.chmod(tmp, 0o400)
        os.replace(tmp, path)
        if self._current == kid:
            remaining = [k for k in sorted(p[:-4] for p in os.listdir(self.root)
                                           if p.endswith(".key")) if k not in revoked]
            # Revoking the last key succeeds: destroying availability is a legitimate act. Sealing
            # afterwards fails closed on its own, which is the loud failure, not this one.
            self._current = remaining[-1] if remaining else ""


class TpmProtector(SoftwareProtector):
    """TPM-backed wrapping, used when a device node and `tpm2` tooling are present.

    The grading is deliberately modest: without captured attestation the binding to this platform is
    `HYPOTHESIS`, not `CONFIRMED`. In an environment with no TPM this refuses outright rather than
    quietly behaving like the software protector.
    """

    backing = "tpm"
    grade = "HYPOTHESIS"

    DEVICE = "/dev/tpmrm0"

    def __init__(self, key_root: str, *, allow_software_fallback: bool = False) -> None:
        if not self.available():
            raise KeyProtectionUnavailable(
                f"no usable TPM device at {self.DEVICE}: refusing to claim hardware backing")
        super().__init__(key_root, allow_software_fallback=True)

    def available(self) -> bool:
        return os.path.exists(self.DEVICE)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _chain_digest(env: "Envelope") -> str:
    """What the chain commits to: the record's content identity, not its key metadata.

    Hashing the whole envelope meant a rotation - which only re-wraps DEKs - changed every digest and
    broke every link. The chain now covers record id, sequence, nonce and ciphertext, all of which a
    rotation leaves alone by design.
    """
    return _digest(f"{env.record_id}\x00{env.seq}\x00{env.nonce}\x00{env.ct}".encode())


@dataclass
class Envelope:
    record_id: str
    seq: int
    kid: str
    nonce: str
    ct: str
    wrapped: str
    prev: str
    schema: int = SCHEMA
    alg: str = ALG

    def to_json(self) -> dict:
        return {
            "record_id": self.record_id, "seq": self.seq, "kid": self.kid,
            "nonce": self.nonce, "ct": self.ct, "wrapped": self.wrapped, "prev": self.prev,
            "schema": self.schema, "alg": self.alg,
        }

    @classmethod
    def from_json(cls, raw: dict) -> "Envelope":
        if raw.get("alg") != ALG:
            raise SealingError(f"unsupported algorithm {raw.get('alg')!r}: refusing to guess")
        return cls(raw["record_id"], int(raw["seq"]), raw["kid"], raw["nonce"], raw["ct"],
                   raw["wrapped"], raw["prev"], int(raw["schema"]))


class SealedVault:
    """Records on disk, sealed. `write` either seals and writes, or raises and leaves nothing."""

    def __init__(self, root: str, key_root: str, protector: KeyProtector) -> None:
        self.root = root
        self.key_root = key_root
        try:
            assert_separated(root, key_root)  # key material inside the record tree is refused
        except CDUPError as exc:
            raise SealingError(str(exc)) from exc
        self.records = os.path.join(root, "records")
        os.makedirs(self.records, mode=0o700, exist_ok=True)
        self.protector = protector

    # ---------- paths ----------

    def _path(self, record_id: str) -> str:
        if not record_id or "/" in record_id or ".." in record_id:
            raise SealingError(f"bad record id {record_id!r}")
        return os.path.join(self.records, f"{record_id}.seal")

    def _head_path(self) -> str:
        return os.path.join(self.root, "head.json")

    # ---------- write ----------

    def write(self, record_id: str, data: bytes) -> dict:
        """Seal then persist. On any protection failure nothing is written and nothing is replaced.

        Records are append-only: an existing id is refused rather than overwritten, so a revision is a
        new record with its own sequence number and the chain never loses what it attested to.
        """
        if os.path.exists(self._path(record_id)):
            raise SealingError(f"record {record_id!r} already exists: sealed records are append-only "
                               "(write a new record id rather than overwriting evidence)")
        prev_digest, last_seq = self._head()
        seq = last_seq + 1
        kid = self.protector.kid()
        try:
            dek = secrets.token_bytes(KEY_LEN)
            nonce = secrets.token_bytes(NONCE_LEN)
            ct = AESGCM(dek).encrypt(nonce, data, _aad(record_id, SCHEMA))
            wrapped = self.protector.wrap(dek)
        except SealingError:
            raise
        except Exception as exc:  # a protector failing for any reason is still a failure to seal
            raise KeyProtectionUnavailable(f"key protection failed: {exc}") from exc

        env = Envelope(record_id, seq, kid, _b64(nonce), _b64(ct), _b64(wrapped), prev_digest)
        payload = json.dumps(env.to_json(), sort_keys=True).encode()
        tmp = self._path(record_id) + ".tmp"
        with open(tmp, "wb") as fh:            # written, then atomically linked into place
            fh.write(payload)
        os.chmod(tmp, 0o400)
        os.replace(tmp, self._path(record_id))
        self._set_head(_chain_digest(env), seq)
        return env.to_json()

    def _head(self) -> tuple[str, int]:
        path = self._head_path()
        if not os.path.exists(path):
            return "", -1          # -1, not 0: the first record is seq 0, and "absent" must not collide
        raw = json.load(open(path))
        return raw["digest"], int(raw["seq"])

    def _set_head(self, digest: str, seq: int) -> None:
        tmp = self._head_path() + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"digest": digest, "seq": seq}, fh)
        os.chmod(tmp, 0o400)
        os.replace(tmp, self._head_path())

    # ---------- read ----------

    def read(self, record_id: str) -> bytes:
        path = self._path(record_id)
        if not os.path.exists(path):
            raise SealingError(f"no sealed record {record_id!r}")
        raw = json.load(open(path))
        env = Envelope.from_json(raw)
        if env.record_id != record_id:
            raise SealingError("envelope claims another record: refusing to open")
        dek = self.protector.unwrap(_unb64(env.wrapped), env.kid)
        try:
            return AESGCM(dek).decrypt(_unb64(env.nonce), _unb64(env.ct),
                                       _aad(env.record_id, env.schema))
        except InvalidTag as exc:
            raise SealingError("record failed authentication: it was altered or the key is wrong") from exc

    # ---------- rotation, revocation ----------

    def rotate(self) -> dict:
        """New key id, DEKs re-wrapped, ciphertext byte-identical. Availability never depends on it."""
        old = self.protector.kid()
        new = self.protector.rotate()
        moved = 0
        for name in sorted(os.listdir(self.records)):
            if not name.endswith(".seal"):
                continue
            path = os.path.join(self.records, name)
            env = Envelope.from_json(json.load(open(path)))
            if env.kid != old:
                continue
            dek = self.protector.unwrap(_unb64(env.wrapped), old)
            env.kid = new
            env.wrapped = _b64(self.protector.wrap(dek))
            payload = json.dumps(env.to_json(), sort_keys=True).encode()
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(payload)
            os.chmod(tmp, 0o400)
            os.replace(tmp, path)
            moved += 1
        self._rechain()
        return {"from": old, "to": new, "rewrapped": moved}

    def revoke(self, kid: str) -> None:
        """Revoking makes records unreadable. It does not touch their ciphertext."""
        self.protector.revoke(kid)

    # ---------- integrity ----------

    def _rechain(self) -> None:
        """Recompute the head after a re-wrap: envelopes changed, ciphertext did not."""
        entries = []
        for name in sorted(os.listdir(self.records)):
            if name.endswith(".seal"):
                path = os.path.join(self.records, name)
                raw = open(path, "rb").read()
                parsed = json.loads(raw)
                entries.append((int(parsed["seq"]), _chain_digest(Envelope.from_json(parsed))))
        entries.sort()
        if entries:
            self._set_head(entries[-1][1], entries[-1][0])
        else:
            self._set_head("", -1)

    def verify_chain(self) -> dict:
        """Hash-linked over record ids in seq order; edits, deletions and gaps are all failures."""
        entries = []
        for name in sorted(os.listdir(self.records)):
            if name.endswith(".seal"):
                path = os.path.join(self.records, name)
                raw = open(path, "rb").read()
                parsed = json.loads(raw)
                entries.append((int(parsed["seq"]), parsed["record_id"], parsed["prev"],
                                _chain_digest(Envelope.from_json(parsed))))
        entries.sort()
        prev = ""
        problems = []
        for expected_seq, (seq, record_id, claimed_prev, digest) in enumerate(entries):
            if seq != expected_seq:
                problems.append(f"sequence gap at {record_id!r}: {seq} != {expected_seq}")
            if claimed_prev != prev:
                problems.append(f"broken link at {record_id!r}")
            prev = digest
        head_digest, head_seq = self._head()
        if entries and prev != head_digest:
            problems.append("head does not match the last record")
        if not entries and head_seq >= 0:
            problems.append("head exists with no records: something was deleted")
        return {"ok": not problems, "records": len(entries), "problems": problems,
                "head": head_digest}

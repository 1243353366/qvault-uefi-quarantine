"""
qvault.cdup
===========

Cryptographic Data Usability Protection.

Objective: **assume the attacker acquires the payload, and minimise what they can recover from it.**

The economics are not subtle. Infostealers are sold as malware-as-a-service, so an attacker who
cannot write malware can still rent collection, and the resulting credential and session-cookie
cache is the input to further intrusion ([1] Recorded Future, 2025). Against that market, the useful
question is not "will the payload be stolen" - assume it will - but "what is a stolen payload worth".

Where encryption helps, and where it does not
---------------------------------------------
CDUP protects two of the four exposure stages, and this module says so rather than implying all four:

1. **Before encryption** - a keylogger, screen capture, or input hook reads plaintext that this
   module has not seen yet. CDUP does nothing here. That is endpoint information-flow security.
2. **During processing** - while a document is decrypted for use it is plaintext in memory. Python
   cannot reliably zeroise. CDUP bounds *when* this happens, not whether it can be observed.
3. **After encryption** - the attacker holds ciphertext and no key. This is CDUP's working case.
4. **During transmission** - same, provided the key path is not compromised.

The load-bearing control is not the cipher. It is the **independent authority**: decryption requires
a capability that the machine holding the ciphertext cannot issue for itself. If the authority runs
on the same host and cooperates automatically with whatever asks, the separation is architectural
decoration and this module is an envelope, not a boundary.

What this does NOT do
---------------------
* Does not defeat a keylogger, screen recorder, or input-capture implant (stage 1).
* Does not protect plaintext in process memory during use (stage 2).
* Does not authenticate the human or the session. A stolen session cookie that can call the
  authority API obtains capabilities; that is an authentication problem one layer out, and it is
  listed as an open test in report/CDUP.md.
* Does not make a compromised endpoint trustworthy. Same host trust gap as the rest of QVault.

[1] Recorded Future, 2025: ~87 stolen credentials per compromised device in their dataset.
"""
from __future__ import annotations

import hmac
import json
import os
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Callable

from qvault.crypto import (KEY_LEN, StreamHeader, canonical_json, decrypt_stream,
                           encrypt_stream, unwrap_key, wrap_key)
from qvault.store import (VaultPaths, get_envelope, put_envelope, read_object, seal_object)

#: Every authorization failure returns this, byte-identical, whatever went wrong. The reason goes to
#: the audit log, which is readable by an authorised observer, not to the caller. A denial that says
#: "expired" versus "wrong object" versus "replayed" is an oracle for whoever is probing.
UNAVAILABLE = "decryption not available"

CAPABILITY_TTL_S = 300
DEFAULT_PRINCIPAL = "unset"


class CDUPError(RuntimeError):
    """An operation refused. The message is deliberately uninformative."""


def _hkdf(key: bytes, info: bytes, length: int = KEY_LEN, salt: bytes = b"") -> bytes:
    """HKDF-SHA256 (RFC 5869), so capability MACs never share a key with the DEK wrapping."""
    prk = hmac.new(salt or b"\x00" * 32, key, sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


@dataclass(frozen=True)
class AuthorityPaths:
    root: str

    @property
    def kek(self) -> str:
        return os.path.join(self.root, "kek.bin")

    @property
    def spent(self) -> str:
        return os.path.join(self.root, "spent.json")


class KeyAuthority:
    """Holds the KEK and mints short-lived decryption capabilities.

    Deployment intent: this lives somewhere the endpoint cannot read - another host, an HSM, a
    smartcard. In-process construction is for tests and for demonstrating the boundary; it does not
    by itself provide one.
    """

    def __init__(self, root: str, *, audit=None, clock: Callable[[], float] = time.time):
        self.paths = AuthorityPaths(root)
        self.audit = audit
        self._clock = clock
        os.makedirs(root, exist_ok=True)

    # ---------- key material ----------

    def _kek(self) -> bytes:
        path = self.paths.kek
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(os.urandom(KEY_LEN))
                fh.flush()
                os.fsync(fh.fileno())
        st = os.stat(path)
        if st.st_mode & 0o077:
            raise CDUPError("key authority misconfigured: key material is not private")
        with open(path, "rb") as fh:
            kek = fh.read()
        if len(kek) != KEY_LEN:
            raise CDUPError("key authority misconfigured: bad key length")
        return kek

    def _mac_key(self) -> bytes:
        return _hkdf(self._kek(), b"qvault-cdup-capability-v1")

    def wrap_dek(self, object_id: str, dek: bytes) -> dict:
        """Envelope-encrypt a DEK under the KEK, bound to the object it belongs to."""
        return wrap_key(self._kek(), dek, aad_obj={"object_id": object_id, "purpose": "cdup"})

    # ---------- capabilities ----------

    def issue(self, object_id: str, principal: str = DEFAULT_PRINCIPAL, *,
              ttl_s: int = CAPABILITY_TTL_S, single_use: bool = True) -> dict:
        """Mint authority for one object. Explicit: nothing here is issued automatically."""
        if ttl_s <= 0:
            raise ValueError("capability lifetime must be positive")
        cap = {
            "object_id": object_id,
            "principal": principal,
            "exp": int(self._clock()) + int(ttl_s),
            "jti": os.urandom(12).hex(),
            "single_use": bool(single_use),
        }
        cap["mac"] = hmac.new(self._mac_key(), canonical_json(cap), sha256).hexdigest()
        self._log("cdup.issue", object_id, {"principal": principal, "jti": cap["jti"],
                                            "exp": cap["exp"], "single_use": cap["single_use"]})
        return cap

    def open_dek(self, wrapped: dict, capability: dict) -> bytes:
        """Return the DEK only if the capability is authentic, current, bound, and unspent."""
        fields = {k: v for k, v in capability.items() if k != "mac"}
        expect = hmac.new(self._mac_key(), canonical_json(fields), sha256).hexdigest()
        if not hmac.compare_digest(expect, str(capability.get("mac", ""))):
            self._deny(capability, "capability mac invalid")
        if int(capability.get("exp", 0)) <= int(self._clock()):
            self._deny(capability, "capability expired")
        if capability.get("object_id") != wrapped_object(wrapped):
            self._deny(capability, "capability bound to a different object")
        jti = str(capability.get("jti", ""))
        spent = self._spent()
        if capability.get("single_use", True) and jti in spent:
            self._deny(capability, "capability already used")
        try:
            dek = unwrap_key(self._kek(), wrapped, aad_obj={"object_id": wrapped_object(wrapped),
                                                            "purpose": "cdup"})
        except Exception:
            self._deny(capability, "wrapped key failed authentication")
        if capability.get("single_use", True):
            self._spend(jti)
        self._log("cdup.open", str(capability.get("object_id")), {"principal": capability.get("principal"),
                                                                 "jti": jti})
        return dek

    # ---------- replay bookkeeping and audit ----------

    def _spent(self) -> set[str]:
        path = self.paths.spent
        if not os.path.exists(path):
            return set()
        with open(path) as fh:
            return set(json.load(fh).get("spent", []))

    def _spend(self, jti: str) -> None:
        spent = sorted(self._spent() | {jti})
        tmp = self.paths.spent + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"spent": spent}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.paths.spent)

    def _deny(self, capability: dict, reason: str) -> None:
        self._log("cdup.deny", str(capability.get("object_id")), {"reason": reason})
        raise CDUPError(UNAVAILABLE)

    def _log(self, event: str, subject: str, payload: dict) -> None:
        if self.audit is not None:
            self.audit.append(event, subject, payload)


def wrapped_object(wrapped: dict) -> str:
    """The object a wrapped key is bound to, as stored in its envelope."""
    return str(wrapped.get("object_id", ""))


def assert_separated(store_root: str, authority_root: str) -> None:
    """Refuse a layout where the authority lives inside the store it protects.

    Same volume is not fatal; the same directory tree is, because every copy of the store then
    carries the key that unlocks it.
    """
    s = os.path.realpath(store_root)
    a = os.path.realpath(authority_root)
    if s == a or a.startswith(s + os.sep) or s.startswith(a + os.sep):
        raise CDUPError("key authority must not share a tree with the store it protects")


# ---------- the two operations a caller actually needs ----------

def put(paths: VaultPaths, authority: KeyAuthority, source_path: str, object_id: str, *,
        principal: str = DEFAULT_PRINCIPAL) -> dict:
    """Encrypt, seal, and wrap the per-object DEK under the authority."""
    assert_separated(paths.root, authority.paths.root)
    size = os.path.getsize(source_path)
    dek = os.urandom(KEY_LEN)
    tmp = os.path.join(paths.root, f".incoming-{os.urandom(6).hex()}")
    with open(source_path, "rb") as src, open(tmp, "wb") as dst:
        header = encrypt_stream(dek, src, dst, plaintext_size=size,
                                aad_obj={"object_id": object_id, "class": "cdup"})
    seal_object(paths, tmp, object_id)
    wrapped = authority.wrap_dek(object_id, dek)
    envelope = {
        "object_id": object_id,
        "cdup": 1,
        "principal": principal,
        "header": header.to_dict(),
        "wrapped_dek": {**wrapped, "object_id": object_id},
    }
    put_envelope(paths, object_id, envelope)
    if authority.audit is not None:
        authority.audit.append("cdup.seal", object_id, {"principal": principal, "size": size})
    return envelope


def get(paths: VaultPaths, authority: KeyAuthority, object_id: str, capability: dict,
        dest_path: str) -> dict:
    """Decrypt one object, if the authority issues for it. Refusal is coarse and audited."""
    assert_separated(paths.root, authority.paths.root)
    env = get_envelope(paths, object_id)
    if not env.get("cdup"):
        raise CDUPError(UNAVAILABLE)
    dek = authority.open_dek(env["wrapped_dek"], capability)
    header = StreamHeader.from_dict(env["header"])
    data = read_object(paths, object_id)
    import io
    src, dst = io.BytesIO(data), open(dest_path, "wb")
    try:
        decrypt_stream(dek, src, dst, header=header,
                       aad_obj={"object_id": object_id, "class": "cdup"})
    finally:
        dst.close()
    return env

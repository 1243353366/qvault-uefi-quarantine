"""
qvault.keys
===========

Key management for the quarantine vault, with split knowledge.

Threat model this addresses
---------------------------
If the KEK that wraps object data keys lives in one file on one host, then
whoever compromises that host can unwrap every sample in the vault. So the
KEK is never stored whole. It is split with Shamir's Secret Sharing over
GF(256) into N shares with a threshold K, and the shares are meant to live
on separate custodians (separate hosts, separate HSMs, separate people).

* Losing any K-1 shares reveals nothing about the KEK.
* Reconstructing the KEK needs K share holders to cooperate, which is a
  real, auditable, human step - not a flag in a config file.
* Every object still gets its own random DEK, so a leaked DEK burns exactly
  one sample.

This module is deliberately dependency-free (no `secretsharing` package) so
the whole mechanism is auditable in one screen.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Iterable, Sequence

KEY_LEN = 32

# GF(2^8) with the AES irreducible polynomial x^8+x^4+x^3+x+1 (0x11B).
_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    """Build exp/log tables using the generator 3.

    Note: 2 is NOT a primitive element of GF(2^8) under the AES polynomial
    0x11B (its multiplicative order is 51), so a naive "shift left" table is
    wrong and silently corrupts Shamir reconstruction. 0x03 is primitive.
    """
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = (x << 1) ^ x  # multiply by 3 (= 2 + 1) in GF(2^8)
        if x & 0x100:
            x ^= 0x11B
        x &= 0xFF
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


@dataclass(frozen=True)
class Share:
    """One custodian's share. `index` is the x coordinate (1..255)."""

    index: int
    y: bytes

    def to_dict(self) -> dict:
        return {"index": self.index, "y": self.y.hex()}

    @classmethod
    def from_dict(cls, d: dict) -> "Share":
        idx = int(d["index"])
        if not 1 <= idx <= 255:
            raise ValueError("share index out of range")
        return cls(idx, bytes.fromhex(d["y"]))


def split(secret: bytes, threshold: int, shares: int) -> list[Share]:
    """Split `secret` into `shares` shares, any `threshold` of which rebuild it."""
    if not 1 <= threshold <= shares <= 255:
        raise ValueError("need 1 <= threshold <= shares <= 255")
    if not secret:
        raise ValueError("cannot split an empty secret")

    polys = []
    for _ in range(len(secret)):
        coeffs = [secret[_]] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        polys.append(coeffs)

    out: list[Share] = []
    for x in range(1, shares + 1):
        y = bytearray()
        for coeffs in polys:
            acc = 0
            for c in reversed(coeffs):
                acc = _mul(acc, x) ^ c
            y.append(acc)
        out.append(Share(x, bytes(y)))
    return out


def combine(shares: Sequence[Share]) -> bytes:
    """Rebuild the secret from `shares` via Lagrange interpolation at x=0."""
    if not shares:
        raise ValueError("no shares supplied")
    xs = [s.index for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices")
    length = len(shares[0].y)
    if any(len(s.y) != length for s in shares):
        raise ValueError("shares have inconsistent length")

    secret = bytearray()
    for pos in range(length):
        acc = 0
        for i, si in enumerate(shares):
            num, den = 1, 1
            for j, sj in enumerate(shares):
                if i == j:
                    continue
                num = _mul(num, sj.index)
                den = _mul(den, sj.index ^ si.index)
            acc ^= _mul(si.y[pos], _div(num, den))
        secret.append(acc)
    return bytes(secret)


def new_kek() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def write_share(path: str, share: Share, *, mode: int = 0o400) -> None:
    """Write a share with owner-read-only permissions."""
    import json

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w") as fh:
        json.dump(share.to_dict(), fh)
        fh.flush()
        os.fsync(fh.fileno())


def read_shares(paths: Iterable[str]) -> list[Share]:
    import json

    out = []
    for p in paths:
        with open(p) as fh:
            out.append(Share.from_dict(json.load(fh)))
    return out

"""CDUP: assume the payload is stolen, then check what the thief can actually do with it.

The tests are written from the attacker's side. Each one acquires something - ciphertext, a
capability, a second capability, a wrapped key - and asserts the recovery still fails, with the same
uninformative refusal every time.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from qvault.audit import AuditLog
from qvault.cdup import (CAPABILITY_TTL_S, UNAVAILABLE, CDUPError, KeyAuthority, get, put)
from qvault.store import VaultPaths, get_envelope


class Clock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def env(tmp_path):
    store = VaultPaths.open(str(tmp_path / "store"))
    clock = Clock()
    audit = AuditLog(str(tmp_path / "audit.log"))
    authority = KeyAuthority(str(tmp_path / "authority"), audit=audit, clock=clock)
    src = tmp_path / "secret.txt"
    src.write_bytes(b"the payload an infostealer would love to have")
    return dict(store=store, authority=authority, clock=clock, audit=audit, src=src,
                tmp=tmp_path, root=tmp_path / "store")


def test_roundtrip_needs_the_authority(env):
    put(env["store"], env["authority"], str(env["src"]), "doc1")
    cap = env["authority"].issue("doc1", "analyst")
    dest = env["tmp"] / "out.txt"
    get(env["store"], env["authority"], "doc1", cap, str(dest))
    assert dest.read_bytes() == env["src"].read_bytes()


def test_the_store_alone_holds_no_key_material(env):
    put(env["store"], env["authority"], str(env["src"]), "doc2")
    for path in Path(env["root"]).rglob("*"):
        assert path.name not in ("kek.bin", "spent.json"), f"key material inside the store: {path}"
    env_text = json.dumps(get_envelope(env["store"], "doc2"))
    assert "kek" not in env_text.lower()


def test_an_expired_capability_is_refused(env):
    put(env["store"], env["authority"], str(env["src"]), "doc3")
    cap = env["authority"].issue("doc3", "analyst", ttl_s=60)
    env["clock"].now += 61
    with pytest.raises(CDUPError):
        env["authority"].open_dek(get_envelope(env["store"], "doc3")["wrapped_dek"], cap)


def test_a_capability_for_one_object_cannot_open_another(env):
    put(env["store"], env["authority"], str(env["src"]), "doc4")
    envelope = get_envelope(env["store"], "doc4")
    cap = env["authority"].issue("some-other-object", "analyst")
    with pytest.raises(CDUPError):
        env["authority"].open_dek(envelope["wrapped_dek"], cap)


def test_a_forged_capability_is_refused(env):
    put(env["store"], env["authority"], str(env["src"]), "doc5")
    envelope = get_envelope(env["store"], "doc5")
    cap = env["authority"].issue("doc5", "analyst")
    cap["exp"] += 10_000  # extend the lifetime without the key
    with pytest.raises(CDUPError):
        env["authority"].open_dek(envelope["wrapped_dek"], cap)


def test_a_capability_is_single_use_by_default(env):
    put(env["store"], env["authority"], str(env["src"]), "doc6")
    envelope = get_envelope(env["store"], "doc6")
    cap = env["authority"].issue("doc6", "analyst")
    env["authority"].open_dek(envelope["wrapped_dek"], cap)
    with pytest.raises(CDUPError):
        env["authority"].open_dek(envelope["wrapped_dek"], cap)


def test_a_repeatable_capability_can_be_used_twice_when_asked_for(env):
    put(env["store"], env["authority"], str(env["src"]), "doc7")
    envelope = get_envelope(env["store"], "doc7")
    cap = env["authority"].issue("doc7", "analyst", single_use=False)
    assert env["authority"].open_dek(envelope["wrapped_dek"], cap)
    assert env["authority"].open_dek(envelope["wrapped_dek"], cap)


def test_swapping_ciphertext_between_objects_fails(env):
    put(env["store"], env["authority"], str(env["src"]), "doc8")
    put(env["store"], env["authority"], str(env["src"]), "doc9")
    a = Path(env["root"]) / "objects" / "doc8.qv"
    b = Path(env["root"]) / "objects" / "doc9.qv"
    pa, pb = a.read_bytes(), b.read_bytes()
    os.chmod(a, 0o600), os.chmod(b, 0o600)
    a.write_bytes(pb), b.write_bytes(pa)  # relabel: put doc9's ciphertext under doc8's name
    cap = env["authority"].issue("doc8", "analyst")
    with pytest.raises(Exception):
        get(env["store"], env["authority"], "doc8", cap, str(env["tmp"] / "x"))


def test_a_capability_from_another_authority_is_refused(env, tmp_path):
    put(env["store"], env["authority"], str(env["src"]), "doc10")
    envelope = get_envelope(env["store"], "doc10")
    rival = KeyAuthority(str(tmp_path / "rival"))
    cap = rival.issue("doc10", "attacker")
    with pytest.raises(CDUPError):
        env["authority"].open_dek(envelope["wrapped_dek"], cap)


def test_every_refusal_reads_the_same(env):
    """Expired, forged, replayed, wrong-object: identical bytes, so the refusal is not an oracle."""
    put(env["store"], env["authority"], str(env["src"]), "doc11")
    envelope = get_envelope(env["store"], "doc11")
    wrapped = envelope["wrapped_dek"]
    messages = []

    expired = env["authority"].issue("doc11", "a", ttl_s=1)
    env["clock"].now += 5
    forged = env["authority"].issue("doc11", "a"); forged["exp"] += 9999
    wrong = env["authority"].issue("other", "a")
    used = env["authority"].issue("doc11", "a")
    env["authority"].open_dek(wrapped, used)

    for cap in (expired, forged, wrong, used):
        with pytest.raises(CDUPError) as exc:
            env["authority"].open_dek(wrapped, cap)
        messages.append(str(exc.value))
    assert set(messages) == {UNAVAILABLE}


def test_the_authority_cannot_live_inside_the_store(env):
    nested = KeyAuthority(str(env["root"]))
    with pytest.raises(CDUPError, match="must not share a tree"):
        put(env["store"], nested, str(env["src"]), "doc12")


def test_refusals_are_audited_with_the_reason(env):
    put(env["store"], env["authority"], str(env["src"]), "doc13")
    envelope = get_envelope(env["store"], "doc13")
    cap = env["authority"].issue("doc13", "analyst", ttl_s=1)
    env["clock"].now += 10
    with pytest.raises(CDUPError):
        env["authority"].open_dek(envelope["wrapped_dek"], cap)
    events = [e["event"] for e in env["audit"].entries()]
    assert "cdup.seal" in events and "cdup.issue" in events and "cdup.deny" in events


def test_the_default_lifetime_is_short():
    assert CAPABILITY_TTL_S <= 600

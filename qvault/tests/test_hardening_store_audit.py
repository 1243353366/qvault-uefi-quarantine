"""The two rows the risk register called riskiest, tested against a store an adversary can write.

Each test builds the attack the register described: a link where a file should be, an object made
writable after seal, an id that traverses, a log truncated and then appended to. The expected answer
is a refusal, and the refusal is coarse.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from qvault.audit import AuditError, AuditLog, verify_checkpoint
from qvault.store import (StoreError, VaultPaths, get_envelope, list_objects, put_envelope,
                          read_object, seal_object)


@pytest.fixture()
def vault(tmp_path) -> VaultPaths:
    return VaultPaths.open(str(tmp_path / "vault"))


def _envelope(vault: VaultPaths, object_id: str = "abc123") -> str:
    path = put_envelope(vault, object_id, {"object_id": object_id, "size": 1})
    assert get_envelope(vault, object_id)["size"] == 1
    return path


def test_a_symlink_in_the_envelope_namespace_is_refused(vault):
    path = Path(_envelope(vault))
    target = Path(vault.root) / "elsewhere.json"
    target.write_text(json.dumps({"object_id": "abc123", "size": 999999}))
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(StoreError):
        get_envelope(vault, "abc123")


def test_an_envelope_made_writable_after_seal_is_refused(vault):
    path = _envelope(vault)
    os.chmod(path, 0o666)
    with pytest.raises(StoreError):
        get_envelope(vault, "abc123")


def test_a_fifo_in_the_envelope_namespace_is_refused_without_hanging(vault):
    path = Path(vault.envelopes) / "fifo1.json"
    os.mkfifo(path)
    with pytest.raises(StoreError):
        get_envelope(vault, "fifo1")


def test_an_object_id_cannot_traverse(vault):
    for bad in ("../secret", "a/b", "..", ""):
        with pytest.raises(StoreError):
            get_envelope(vault, bad)
        with pytest.raises(StoreError):
            put_envelope(vault, bad, {"x": 1})


def test_sealed_ciphertext_round_trips_through_the_guarded_reader(vault, tmp_path):
    tmp = tmp_path / "blob"
    tmp.write_bytes(b"ciphertext-bytes")
    sealed = seal_object(vault, str(tmp), "obj1")
    assert read_object(vault, "obj1") == b"ciphertext-bytes"
    os.chmod(sealed, 0o660)  # group-writable after seal; the reader refuses it
    with pytest.raises(StoreError):
        read_object(vault, "obj1")


def test_a_regular_object_still_reads_after_the_directory_fsync(vault, tmp_path):
    tmp = tmp_path / "blob2"
    tmp.write_bytes(b"x")
    seal_object(vault, str(tmp), "obj2")
    assert [e["object_id"] for e in list_objects(vault)] == []  # no envelope yet, but no error


def test_appending_after_a_truncation_is_refused(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    for i in range(3):
        log.append("seal", f"obj{i}", {"i": i})
    assert log.verify()[0]
    path = Path(log.path)
    kept = path.read_text().splitlines()[:1]
    path.write_text("\n".join(kept) + "\n")
    assert log.verify()[0], "a truncated chain is internally valid; that is the whole problem"
    with pytest.raises(AuditError, match="high-water mark"):
        log.append("seal", "obj3", {})


def test_a_symlinked_audit_log_is_refused(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    log.append("seal", "obj0", {})
    real = Path(tmp_path) / "real.log"
    Path(log.path).rename(real)
    Path(log.path).symlink_to(real)
    with pytest.raises(AuditError):
        log.entries()


def test_the_checkpoint_still_catches_truncation_that_the_mark_cannot(tmp_path):
    """Two independent controls: the local mark refuses growth, the signed head catches shrinkage."""
    log = AuditLog(str(tmp_path / "audit.log"))
    for i in range(4):
        log.append("seal", f"obj{i}", {"i": i})
    log.init_signing_key()
    cp = log.checkpoint(str(tmp_path / "cp.json"))
    Path(log.path).write_text("")
    Path(log.path + ".hwm").unlink()
    ok, why = verify_checkpoint(cp, log)
    assert not ok and "truncation" in why

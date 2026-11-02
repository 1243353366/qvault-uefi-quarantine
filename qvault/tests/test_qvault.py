"""End-to-end tests for the quarantine vault.

These tests use synthetic byte strings only. No real malware is present, and
the suite must never be pointed at a live sample.
"""

from __future__ import annotations

import json
import os

import pytest

from qvault import store
from qvault.audit import AuditLog, verify_checkpoint
from qvault.crypto import CryptoError, decrypt_stream, encrypt_stream, StreamHeader
from qvault.ingest import ingest
from qvault.keys import combine, split
from qvault.retrieve import (
    AuthorizationError,
    load_approvals,
    record_approval,
    retrieve,
)
from qvault.triage import shannon_entropy, triage_bytes
from qvault.verify import verify_vault

# A synthetic "firmware-ish" blob: SPI descriptor magic, an FV header, and an
# indicator token. It is not malware and is not executable.
FAKE_FIRMWARE = (
    b"\x00" * 0x10
    + b"\x5a\xa5\xf0\x0f"
    + b"\x00" * 0x40
    + b"_FVH"
    + b"\x00" * 0x100
    + b"SecDxe\x00"
    + b"C:\\edk2\\NtfsPkg\\NtfsDxe\\ntfs\\mft.c\x00"
    + os.urandom(2048)
)


@pytest.fixture()
def vault(tmp_path):
    root = str(tmp_path / "vault")
    paths = store.VaultPaths.open(root)
    from hashlib import sha256
    from qvault.crypto import canonical_json
    from qvault.keys import new_kek

    kek = new_kek()
    shares = split(kek, 2, 3)
    custodian = tmp_path / "custodian"
    custodian.mkdir()
    for sh in shares:
        with open(custodian / f"share-{sh.index}.json", "w") as fh:
            json.dump(sh.to_dict(), fh)

    log = AuditLog(paths.audit)
    log.init_signing_key(os.path.join(root, "audit-signing.key"))
    store.write_once(
        os.path.join(root, "vault.json"),
        canonical_json(
            {
                "version": 1,
                "kek_id": sha256(kek).hexdigest()[:32],
                "threshold": 2,
                "shares": 3,
                "approvals_required": 2,
            }
        ),
        mode=0o400,
    )
    return {
        "root": root,
        "paths": paths,
        "kek": kek,
        "shares": shares,
        "custodian": custodian,
        "log": log,
    }


def _write(tmp_path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_roundtrip_preserves_bytes_exactly(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(
        vault["paths"],
        vault["kek"],
        src,
        operator="analyst",
        method="synthetic fixture",
    )
    assert env["plaintext_size"] == len(FAKE_FIRMWARE)
    assert env["object_id"] == env["ciphertext_sha256"]

    enclave = tmp_path / "enclave"
    enclave.mkdir()
    (enclave / ".enclave").write_text("analysis enclave")

    record_approval(vault["paths"], env["object_id"], "reviewer1", justification="case A")
    record_approval(vault["paths"], env["object_id"], "reviewer2", justification="case A")

    out = retrieve(
        vault["paths"],
        env["object_id"],
        shares=vault["shares"][:2],
        threshold=2,
        requester="analyst",
        out_dir=str(enclave),
    )
    assert open(out, "rb").read() == FAKE_FIRMWARE


def test_plaintext_is_never_written_during_ingest(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    # The sealed object must not contain the plaintext in the clear.
    blob = open(store.object_path(vault["paths"], env["object_id"]), "rb").read()
    assert FAKE_FIRMWARE[:64] not in blob
    assert b"SecDxe" not in blob


def test_single_bit_tamper_is_detected(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    path = store.object_path(vault["paths"], env["object_id"])
    os.chmod(path, 0o600)
    with open(path, "r+b") as fh:
        fh.seek(100)
        b = fh.read(1)
        fh.seek(100)
        fh.write(bytes([b[0] ^ 0x01]))
    os.chmod(path, 0o400)

    rep = verify_vault(vault["paths"])
    assert not rep.ok
    assert any("ciphertext hash mismatch" in e for e in rep.errors)


def test_decryption_with_wrong_key_fails_closed(tmp_path):
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    aad = {"envelope_id": "x", "plaintext_size": 5, "source_label": "s"}
    out = tmp_path / "ct.bin"
    with open(tmp_path / "pt.bin", "wb") as fh:
        fh.write(b"hello")
    with open(tmp_path / "pt.bin", "rb") as src, open(out, "wb") as dst:
        header = encrypt_stream(key_a, src, dst, plaintext_size=5, aad_obj=aad)

    with open(out, "rb") as src, open(tmp_path / "bad.bin", "wb") as dst:
        with pytest.raises(CryptoError):
            decrypt_stream(key_b, src, dst, header=header, aad_obj=aad)


def test_chunk_boundary_sizes_roundtrip(tmp_path):
    """Exercise empty, sub-chunk, exact-chunk and multi-chunk inputs."""
    for size in (0, 1, 65535, 65536, 65537, 200000):
        data = os.urandom(size)
        key = os.urandom(32)
        aad = {"envelope_id": f"s{size}", "plaintext_size": size, "source_label": "x"}
        (tmp_path / "in").write_bytes(data)
        with open(tmp_path / "in", "rb") as src, open(tmp_path / "ct", "wb") as dst:
            header = encrypt_stream(key, src, dst, plaintext_size=size, aad_obj=aad)
        with open(tmp_path / "ct", "rb") as src, open(tmp_path / "out", "wb") as dst:
            decrypt_stream(key, src, dst, header=header, aad_obj=aad)
        assert (tmp_path / "out").read_bytes() == data


def test_truncated_ciphertext_is_rejected(tmp_path):
    data = os.urandom(70000)
    key = os.urandom(32)
    aad = {"envelope_id": "t", "plaintext_size": len(data), "source_label": "x"}
    (tmp_path / "in").write_bytes(data)
    with open(tmp_path / "in", "rb") as src, open(tmp_path / "ct", "wb") as dst:
        header = encrypt_stream(key, src, dst, plaintext_size=len(data), aad_obj=aad)
    blob = (tmp_path / "ct").read_bytes()[:-10]
    (tmp_path / "ct2").write_bytes(blob)
    with open(tmp_path / "ct2", "rb") as src, open(tmp_path / "out", "wb") as dst:
        with pytest.raises(CryptoError):
            decrypt_stream(key, src, dst, header=header, aad_obj=aad)


def test_header_swap_is_rejected(tmp_path):
    """Ciphertext from object A must not decrypt under object B's metadata."""
    data = os.urandom(1000)
    key = os.urandom(32)
    aad_a = {"envelope_id": "a", "plaintext_size": 1000, "source_label": "a"}
    aad_b = {"envelope_id": "b", "plaintext_size": 1000, "source_label": "b"}
    (tmp_path / "in").write_bytes(data)
    with open(tmp_path / "in", "rb") as src, open(tmp_path / "ct", "wb") as dst:
        header = encrypt_stream(key, src, dst, plaintext_size=1000, aad_obj=aad_a)
    with open(tmp_path / "ct", "rb") as src, open(tmp_path / "out", "wb") as dst:
        with pytest.raises(CryptoError):
            decrypt_stream(key, src, dst, header=header, aad_obj=aad_b)


def test_quorum_below_threshold_is_refused(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    enclave = tmp_path / "enclave"
    enclave.mkdir()
    (enclave / ".enclave").write_text("ok")
    record_approval(vault["paths"], env["object_id"], "r1", justification="j")
    record_approval(vault["paths"], env["object_id"], "r2", justification="j")

    with pytest.raises(AuthorizationError, match="quorum"):
        retrieve(
            vault["paths"],
            env["object_id"],
            shares=vault["shares"][:1],
            threshold=2,
            requester="analyst",
            out_dir=str(enclave),
        )


def test_dual_control_requires_two_independent_approvers(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    enclave = tmp_path / "enclave"
    enclave.mkdir()
    (enclave / ".enclave").write_text("ok")
    record_approval(vault["paths"], env["object_id"], "r1", justification="j")

    with pytest.raises(AuthorizationError, match="dual control"):
        retrieve(
            vault["paths"],
            env["object_id"],
            shares=vault["shares"][:2],
            threshold=2,
            requester="analyst",
            out_dir=str(enclave),
        )


def test_requester_cannot_self_approve(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    enclave = tmp_path / "enclave"
    enclave.mkdir()
    (enclave / ".enclave").write_text("ok")
    record_approval(vault["paths"], env["object_id"], "analyst", justification="self")
    record_approval(vault["paths"], env["object_id"], "r2", justification="ok")

    with pytest.raises(AuthorizationError, match="dual control"):
        retrieve(
            vault["paths"],
            env["object_id"],
            shares=vault["shares"][:2],
            threshold=2,
            requester="analyst",
            out_dir=str(enclave),
        )


def test_retrieval_outside_enclave_is_refused(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    record_approval(vault["paths"], env["object_id"], "r1", justification="j")
    record_approval(vault["paths"], env["object_id"], "r2", justification="j")
    plain = tmp_path / "not-an-enclave"
    plain.mkdir()

    with pytest.raises(AuthorizationError, match="enclave"):
        retrieve(
            vault["paths"],
            env["object_id"],
            shares=vault["shares"][:2],
            threshold=2,
            requester="analyst",
            out_dir=str(plain),
        )


def test_retrieved_file_is_not_executable(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    enclave = tmp_path / "enclave"
    enclave.mkdir()
    (enclave / ".enclave").write_text("ok")
    record_approval(vault["paths"], env["object_id"], "r1", justification="j")
    record_approval(vault["paths"], env["object_id"], "r2", justification="j")
    out = retrieve(
        vault["paths"],
        env["object_id"],
        shares=vault["shares"][:2],
        threshold=2,
        requester="analyst",
        out_dir=str(enclave),
    )
    assert os.stat(out).st_mode & 0o777 == 0o400


def test_audit_chain_detects_edits_and_truncation(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    log = vault["log"]
    cp = log.checkpoint(os.path.join(vault["paths"].checkpoints, "cp1.json"))

    ok, _ = log.verify()
    assert ok

    # Edit a payload hash in the middle of the log.
    lines = open(vault["paths"].audit).read().splitlines()
    entry = json.loads(lines[-1])
    entry["payload_hash"] = "0" * 64
    lines[-1] = json.dumps(entry, sort_keys=True)
    open(vault["paths"].audit, "w").write("\n".join(lines) + "\n")

    ok, msg = log.verify()
    assert not ok and "hash mismatch" in msg

    # Restore, then truncate: the signed checkpoint must catch it.
    lines[-1] = json.dumps(AuditLog(vault["paths"].audit).entries()[-1], sort_keys=True)
    open(vault["paths"].audit, "w").write("\n".join(lines[:-1]) + "\n")
    ok, msg = verify_checkpoint(cp, log)
    assert not ok


def test_shamir_threshold_math():
    """Any K shares recover the secret; K-1 shares yield garbage, not an error.

    That is the security property: below the threshold there is no signal that
    you are close, and no error to oracle against.
    """
    secret = os.urandom(32)
    shares = split(secret, 3, 5)
    assert combine(shares[:3]) == secret
    assert combine([shares[0], shares[2], shares[4]]) == secret
    assert combine(shares[:2]) != secret
    assert combine(shares[0:1]) != secret


def test_triage_reads_structures_without_parsing(vault, tmp_path):
    res = triage_bytes(FAKE_FIRMWARE)
    assert any("intel_spi_flash_descriptor" in m for m in res.magic)
    assert any("firmware_volume" in m for m in res.magic)
    assert "SecDxe" in res.ioc_hits

    random_blob = os.urandom(8192)
    res2 = triage_bytes(random_blob)
    assert res2.ioc_hits == []
    assert res2.high_entropy_blocks / max(res2.entropy_blocks, 1) > 0.5
    assert shannon_entropy(b"\x00" * 4096) == 0.0


def test_verify_reports_orphan_objects(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", FAKE_FIRMWARE)
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    orphan = os.path.join(vault["paths"].objects, "deadbeef" * 8 + ".qv")
    store.write_once(orphan, b"not-a-real-object")
    rep = verify_vault(vault["paths"])
    assert any("orphan object" in e for e in rep.errors)


def test_merkle_root_changes_when_inventory_changes(vault, tmp_path):
    a = vault["paths"]
    root_empty = store.merkle_root([])
    ingest(a, vault["kek"], _write(tmp_path, "one.bin", b"one"), operator="o", method="m")
    root_one = store.merkle_root(sorted(e["object_id"] for e in store.list_objects(a)))
    ingest(a, vault["kek"], _write(tmp_path, "two.bin", b"two"), operator="o", method="m")
    root_two = store.merkle_root(sorted(e["object_id"] for e in store.list_objects(a)))
    assert len({root_empty, root_one, root_two}) == 3


def test_stream_header_rejects_hostile_counts_before_decrypt(tmp_path):
    from qvault.crypto import CHUNK_SIZE, SUITE

    malformed = [
        {"suite": SUITE, "chunk_size": CHUNK_SIZE, "n_chunks": 10**30,
         "plaintext_size": 1},
        {"suite": SUITE, "chunk_size": CHUNK_SIZE, "n_chunks": 0,
         "plaintext_size": 0},
        {"suite": SUITE, "chunk_size": CHUNK_SIZE, "n_chunks": 1,
         "plaintext_size": -1},
        {"suite": SUITE, "chunk_size": CHUNK_SIZE, "n_chunks": True,
         "plaintext_size": 1},
    ]
    for item in malformed:
        with pytest.raises(CryptoError):
            StreamHeader.from_dict(item)


def test_share_combine_rejects_out_of_range_manual_index():
    from qvault.keys import Share

    with pytest.raises(ValueError, match="index"):
        combine([Share(0, b"x")])


def test_approval_identity_cannot_escape_approval_directory(vault):
    from qvault.retrieve import AuthorizationError

    with pytest.raises(AuthorizationError, match="safe identifier"):
        record_approval(vault["paths"], "a" * 64, "../../outside", justification="no")


def test_retrieve_rejects_path_filename_and_preserves_existing_file(vault, tmp_path):
    src = _write(tmp_path, "dump.bin", b"fixture")
    env = ingest(vault["paths"], vault["kek"], src, operator="a", method="m")
    enclave = tmp_path / "enclave"
    enclave.mkdir()
    (enclave / ".enclave").write_text("ok")
    record_approval(vault["paths"], env["object_id"], "r1", justification="j")
    record_approval(vault["paths"], env["object_id"], "r2", justification="j")

    with pytest.raises(AuthorizationError, match="safe filename"):
        retrieve(vault["paths"], env["object_id"], shares=vault["shares"][:2],
                 threshold=2, requester="analyst", out_dir=str(enclave), filename="../escape")

    existing = enclave / "kept.sample"
    existing.write_bytes(b"do not overwrite")
    with pytest.raises(AuthorizationError, match="overwrite"):
        retrieve(vault["paths"], env["object_id"], shares=vault["shares"][:2],
                 threshold=2, requester="analyst", out_dir=str(enclave), filename="kept.sample")
    assert existing.read_bytes() == b"do not overwrite"


def test_ingest_encrypts_and_triages_same_source_bytes(vault, tmp_path, monkeypatch):
    import qvault.ingest as ingest_module

    initial = b"A" * 65536 + b"B" * 1024
    changed = b"C" * len(initial)
    source = _write(tmp_path, "dump.bin", initial)
    real_encrypt = ingest_module.encrypt_stream

    def mutate_before_encryption(*args, **kwargs):
        # Change the already-open inode at the exact point encryption begins.
        # Hash and ciphertext must describe the same bytes, never two passes.
        with open(source, "r+b") as fh:
            fh.write(changed)
            fh.flush()
        return real_encrypt(*args, **kwargs)

    monkeypatch.setattr(ingest_module, "encrypt_stream", mutate_before_encryption)
    env = ingest(vault["paths"], vault["kek"], source, operator="a", method="m")
    assert env["plaintext_size"] == len(changed)
    assert env["plaintext_sha256"] == __import__("hashlib").sha256(changed).hexdigest()

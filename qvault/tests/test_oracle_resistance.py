"""Oracle problems: what an interface must not tell an attacker.

An oracle is any observable answer to a question the attacker should not be able to ask.
These tests assert indistinguishability, not merely that an error was raised.
"""
from __future__ import annotations

import io
import tempfile

import pytest

from qvault import crypto, keys, retrieve, store


def _vault():
    return store.VaultPaths.open(tempfile.mkdtemp() + "/v")


def _roundtrip(plaintext: bytes):
    """Encrypt in memory and return (header, ciphertext bytes, kek)."""
    kek = keys.new_kek()
    hdr = crypto.StreamHeader(suite=crypto.SUITE, chunk_size=crypto.CHUNK_SIZE,
                             plaintext_size=len(plaintext))
    dst = io.BytesIO()
    crypto.encrypt_stream(plaintext, io.BytesIO(plaintext), dst)
    return kek, hdr, dst.getvalue()


def test_a_tampered_chunk_says_nothing_about_position():
    """An index would let an attacker bisect where their edit was detected."""
    import os

    directory = tempfile.mkdtemp()
    kek = keys.new_kek()
    payload = b"C" * 20000
    src_path = os.path.join(directory, "c.bin")
    with open(src_path, "wb") as fh:
        # encrypt_stream returns the header it used: no need to hand-build one
        hdr = crypto.encrypt_stream(kek, io.BytesIO(payload), fh,
                                    plaintext_size=len(payload), aad_obj={"object_id": "x"})
    blob = open(src_path, "rb").read()

    messages = set()
    for flip in (40, 900, 5000):
        bad = bytearray(blob)
        bad[flip] ^= 0x01
        with pytest.raises(crypto.CryptoError) as exc:
            crypto.decrypt_stream(kek, io.BytesIO(bytes(bad)), io.BytesIO(),
                                  header=hdr, aad_obj={"object_id": "x"})
        messages.add(str(exc.value))
    assert messages == {crypto.AUTH_FAILED}, messages


def test_the_failure_message_names_no_position_or_key_property():
    for leak in ("chunk", "index", "wrong key", "quorum", "length", "nonce"):
        assert leak not in crypto.AUTH_FAILED.lower(), leak


def test_object_and_envelope_absence_are_indistinguishable():
    """Distinct errors would reveal an aborted ingest: object present, envelope missing."""
    paths = _vault()
    oid = "a" * 64
    messages = []
    for call in (lambda: store.get_envelope(paths, oid), lambda: store.object_path(paths, oid)):
        with pytest.raises(store.StoreError) as exc:
            call()
        messages.append(str(exc.value))
    assert messages[0] == messages[1]


def test_provenance_digest_comparison_is_constant_time():
    import inspect

    from qvault import provenance
    assert "compare_digest" in inspect.getsource(provenance.verify)


def test_fewer_than_threshold_shares_carry_no_signal():
    kek = keys.new_kek()
    shares = keys.split(kek, 3, 5)
    a = keys.combine(shares[:2])
    b = keys.combine([shares[0], shares[1]])
    assert a == b, "the same K-1 shares are deterministic"
    assert a != kek, "K-1 shares must not reconstruct the secret"


def test_a_wrong_share_raises_nothing_distinctive():
    kek = keys.new_kek()
    shares = keys.split(kek, 2, 3)
    forged = keys.Share(index=shares[2].index, y=bytes(32))
    out = keys.combine([shares[0], forged])
    assert out != kek
    assert isinstance(out, bytes), "no exception shape to distinguish a bad share by"


def _sealed_object():
    """One real sealed object, so the approval gate is reached rather than the lookup."""
    import os

    from qvault import ingest as ingest_mod
    paths = _vault()
    kek = keys.new_kek()
    src = os.path.join(tempfile.mkdtemp(), "artifact.bin")
    with open(src, "wb") as fh:
        fh.write(b"evidence")
    env = ingest_mod.ingest(paths, kek, src, operator="analyst", method="oob_spi_read")
    return paths, env["object_id"]


def test_dual_control_reports_a_count_not_the_other_approvers():
    paths, oid = _sealed_object()
    retrieve.record_approval(paths, oid, approver="c1", justification="ticket 1")
    with pytest.raises(retrieve.AuthorizationError) as exc:
        retrieve.retrieve(paths, oid, shares=[], threshold=2, requester="analyst",
                          out_dir=tempfile.mkdtemp(), approvals_required=2)
    text = str(exc.value)
    assert "1 of 2" in text
    assert "c1" not in text, "the requester must not learn which approver acted"


def test_reapproval_does_not_enumerate_others():
    paths = _vault()
    oid = "c" * 64
    retrieve.record_approval(paths, oid, approver="c1", justification="t")
    with pytest.raises(retrieve.AuthorizationError) as exc:
        retrieve.record_approval(paths, oid, approver="c1", justification="t")
    text = str(exc.value)
    assert "c1" in text
    assert "c2" not in text


def test_no_secret_derived_value_is_compared_with_a_plain_operator():
    """A short-circuiting != on a secret-derived digest is a timing oracle.

    Callers can vary a reconstructed KEK freely by choosing shares, so the comparison
    must not reveal how many leading characters matched.
    """
    import pathlib as _p

    root = _p.Path(__file__).resolve().parents[1]
    secrets = ("kek", "dek", "share", "secret")
    offenders = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts or "vendor" in path.parts:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            low = line.lower()
            if low.strip().startswith("#") or "compare_digest" in low:
                continue
            if "!=" not in low:
                continue
            if ("hexdigest" in low or "digest(" in low) and any(w in low for w in secrets):
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert not offenders, f"non-constant-time comparison on a secret: {offenders}"

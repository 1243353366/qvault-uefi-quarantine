"""Attestation only counts if it is evidence. Each test removes one thing evidence needs and requires
the verdict to say so, because an evaluator that accepts a claim is the defect this module exists for."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qvault import attestation as att

PCRS = "sha256:0,1,2,7"
PCR_DIGEST = "9f" * 32
RECEIPT = "1a" * 32
NONCE = "nonce-for-this-verification"


def _pki():
    """Root CA -> intermediate -> attestation key, all EC for speed."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    root = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qvault test root")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qvault test root")]))
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256()))
    ak_key = ec.generate_private_key(ec.SECP256R1())
    ak = (x509.CertificateBuilder()
          .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attestation key")]))
          .issuer_name(root.subject).public_key(ak_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
          .sign(root_key, hashes.SHA256()))
    pem = [ak.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM).decode()]
    return root, root_key, ak, ak_key, pem


@pytest.fixture()
def pki():
    return _pki()


def evidence(pki, **over):
    _, _, ak, ak_key, pem = pki
    stmt = att.AttestationStatement(nonce=over.pop("nonce", NONCE), receipt_digest=over.pop("receipt", RECEIPT),
                                    pcr_selection=over.pop("selection", PCRS),
                                    pcr_digest=over.pop("pcr", PCR_DIGEST),
                                    ak_name=over.pop("ak_name", att.key_fingerprint(ak.public_key())), **over)
    return att.AttestationEvidence(statement=stmt, chain_pem=pem).sign(ak_key)


def check(pki, ev, **over):
    args = dict(receipt_digest=RECEIPT, expected_nonce=NONCE, anchors=[pki[0]],
                pcr_policy=att.PcrPolicy(selection=PCRS, expected_digest=PCR_DIGEST))
    args.update(over)
    return att.verify_attestation(ev, **args)


def test_complete_evidence_confirms(pki):
    out = check(pki, evidence(pki))
    assert out["grade"] == "CONFIRMED", out["failed_checks"]
    assert out["ak_name"] == att.key_fingerprint(pki[2].public_key())


def test_absent_evidence_is_not_a_pass(pki):
    out = check(pki, None)
    assert out["grade"] == "HYPOTHESIS"
    assert out["ok"] is False


def test_no_anchor_means_nothing_to_check_against(pki):
    out = check(pki, evidence(pki), anchors=[])
    assert out["grade"] == "REFUSED"
    assert any("trust anchor" in r for r in out["reasons"])


def test_a_self_signed_key_is_not_an_anchor(pki):
    """The classic shortcut: present a key and its own signature and call it attested."""
    root, _, _, _, _ = pki
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    rogue_key = _ec.generate_private_key(_ec.SECP256R1())
    now = datetime.now(timezone.utc)
    rogue = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attestation key")]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attestation key")]))
             .public_key(rogue_key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .sign(rogue_key, hashes.SHA256()))
    stmt = att.AttestationStatement(nonce=NONCE, receipt_digest=RECEIPT, pcr_selection=PCRS,
                                    pcr_digest=PCR_DIGEST,
                                    ak_name=att.key_fingerprint(rogue_key.public_key()))
    ev = att.AttestationEvidence(stmt, [rogue.public_bytes(serialization.Encoding.PEM).decode()]).sign(rogue_key)
    out = check(pki, ev)
    assert out["grade"] == "REFUSED"
    assert any("trust anchor" in r for r in out["failed_checks"])


def test_a_stale_quote_is_refused(pki):
    out = check(pki, evidence(pki), expected_nonce="a-different-nonce")
    assert out["grade"] == "REFUSED"
    assert any("replayed or stale" in r for r in out["failed_checks"])


def test_age_alone_refutes_a_quote(pki):
    old = replace(evidence(pki), statement=replace(evidence(pki).statement,
                 generated_at="2026-01-01T00:00:00Z"))
    out = check(pki, old, expected_nonce=NONCE)
    assert out["grade"] == "REFUSED"
    assert any("freshness" in r for r in out["failed_checks"])


def test_evidence_cannot_be_moved_to_another_receipt(pki):
    out = check(pki, evidence(pki), receipt_digest="ff" * 32)
    assert out["grade"] == "REFUSED"
    assert any("different receipt" in r for r in out["failed_checks"])


def test_a_bare_quote_without_measurements_is_refused(pki):
    out = check(pki, evidence(pki), pcr_policy=None)
    assert out["grade"] == "REFUSED"
    assert any("measurement policy" in r for r in out["reasons"])


def test_measurements_must_match_the_policy(pki):
    out = check(pki, evidence(pki), pcr_policy=att.PcrPolicy(selection=PCRS, expected_digest="00" * 32))
    assert out["grade"] == "REFUSED"
    assert any("PCR digest" in r for r in out["failed_checks"])


def test_the_selection_must_match_too(pki):
    out = check(pki, evidence(pki), pcr_policy=att.PcrPolicy(selection="sha256:0,1", expected_digest=PCR_DIGEST))
    assert out["grade"] == "REFUSED"
    assert any("selection" in r for r in out["failed_checks"])


def test_a_tampered_statement_breaks_the_signature(pki):
    ev = evidence(pki)
    forged = replace(ev, statement=replace(ev.statement, pcr_digest="00" * 32))
    out = check(pki, forged, pcr_policy=att.PcrPolicy(selection=PCRS, expected_digest="00" * 32))
    assert out["grade"] == "REFUSED"
    assert any("does not verify" in r for r in out["failed_checks"])


def test_an_unrelated_signing_key_is_refused(pki):
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    ev = evidence(pki)
    stray = _ec.generate_private_key(_ec.SECP256R1()).sign(b"x", __import__(
        "cryptography.hazmat.primitives.asymmetric.ec", fromlist=["ECDSA"]).ECDSA(
        __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()))
    out = check(pki, replace(ev, signature=stray.hex()))
    assert out["grade"] == "REFUSED"


def test_an_expired_certificate_is_refused(pki):
    root, root_key, ak, ak_key, _ = pki
    now = datetime.now(timezone.utc)
    expired = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attestation key")]))
               .issuer_name(root.subject).public_key(ak_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=365)).not_valid_after(now - timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .sign(root_key, hashes.SHA256()))
    from cryptography.hazmat.primitives import serialization
    stmt = att.AttestationStatement(nonce=NONCE, receipt_digest=RECEIPT, pcr_selection=PCRS,
                                    pcr_digest=PCR_DIGEST,
                                    ak_name=att.key_fingerprint(ak_key.public_key()))
    ev = att.AttestationEvidence(stmt, [expired.public_bytes(serialization.Encoding.PEM).decode()]).sign(ak_key)
    out = check(pki, ev)
    assert out["grade"] == "REFUSED"
    assert any("validity window" in r for r in out["failed_checks"])


def test_the_leaf_cannot_be_a_ca(pki):
    root, root_key, _, ak_key, _ = pki
    now = datetime.now(timezone.utc)
    from cryptography.hazmat.primitives import serialization
    leaf_ca = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attestation key")]))
               .issuer_name(root.subject).public_key(ak_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .sign(root_key, hashes.SHA256()))
    stmt = att.AttestationStatement(nonce=NONCE, receipt_digest=RECEIPT, pcr_selection=PCRS,
                                    pcr_digest=PCR_DIGEST,
                                    ak_name=att.key_fingerprint(ak_key.public_key()))
    ev = att.AttestationEvidence(stmt, [leaf_ca.public_bytes(serialization.Encoding.PEM).decode()]).sign(ak_key)
    out = check(pki, ev)
    assert out["grade"] == "REFUSED"
    assert any("CA certificate" in r for r in out["failed_checks"])


def test_a_chain_that_does_not_link_is_refused(pki):
    """A leaf plus an unrelated anchor: the anchor is genuine, the link is missing."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    ev = evidence(pki)
    other_root = _ec.generate_private_key(_ec.SECP256R1())
    now = datetime.now(timezone.utc)
    stray = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other root")]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "other root")]))
             .public_key(other_root.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .sign(other_root, hashes.SHA256()))
    out = check(pki, ev, anchors=[stray])
    assert out["grade"] == "REFUSED"
    assert any("trust anchor" in r for r in out["failed_checks"])


def test_evidence_round_trips_through_a_bundle(pki):
    ev = evidence(pki)
    back = att.AttestationEvidence.from_dict(ev.to_dict())
    assert check(pki, back)["grade"] == "CONFIRMED"

"""Four elements, checked separately. The tests that matter are the ones where one element fails and
the others must still report, and the ones where a label is not proof of a key."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qvault import attestation as att
from qvault import authorization as az

PLAINTEXT = "b" * 64
CIPHERTEXT = "a" * 64
NONCE = "verifier-chosen-nonce"
PCRS = "sha256:0,1,2,7"
PCR_DIGEST = "9f" * 32


def _pki():
    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qvault test root")])
    root = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
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
    from cryptography.hazmat.primitives import serialization
    return root, ak, ak_key, [ak.public_bytes(serialization.Encoding.PEM).decode()]


def _evidence(pki, receipt_digest, **over):
    _, ak, ak_key, pem = pki
    stmt = att.AttestationStatement(nonce=over.pop("nonce", NONCE), receipt_digest=receipt_digest,
                                    pcr_selection=PCRS, pcr_digest=PCR_DIGEST,
                                    ak_name=att.key_fingerprint(ak.public_key()), **over)
    return att.AttestationEvidence(stmt, pem).sign(ak_key)


@pytest.fixture()
def world(tmp_path):
    root, req, a1, a2, a3, ex = (Ed25519PrivateKey.generate() for _ in range(6))
    policy = az.AuthorityPolicy(members={
        az.fingerprint(req.public_key()): ["request"],
        az.fingerprint(a1.public_key()): ["approve"],
        az.fingerprint(a2.public_key()): ["approve"],
        az.fingerprint(a3.public_key()): ["request"],       # may ask, may not approve
        az.fingerprint(ex.public_key()): ["execute"],
    }, threshold=2).sign(root)
    draft = az.Intent(object_id="obj-1", ciphertext_sha256=CIPHERTEXT, purpose="decrypt",
                      requester="", policy_digest=policy.digest, threshold=2)
    intent = draft.sign(req)
    approvals = [az.Approval(intent_digest="", approver="").sign(a1, intent),
                 az.Approval(intent_digest="", approver="").sign(a2, intent)]
    receipt = az.Receipt(intent_digest=intent.digest, object_id="obj-1",
                         plaintext_sha256=PLAINTEXT, executor="", attestation="tpm_quote").sign(ex)
    keys = {az.fingerprint(k.public_key()): k.public_key() for k in (req, a1, a2, a3, ex)}
    pki = _pki()
    return {
        "pki": pki,
        "anchor": pki[0],
        "evidence": _evidence(pki, receipt.digest),
        "nonce": NONCE,
        "pcr": att.PcrPolicy(selection=PCRS, expected_digest=PCR_DIGEST),
        "root": root, "req": req, "a1": a1, "a2": a2, "a3": a3, "ex": ex,
        "policy": policy, "intent": intent, "approvals": approvals, "receipt": receipt,
        "keys": keys, "nonces": az.NonceStore(str(tmp_path / "nonces.txt")),
    }


def verify(w, **over):
    args = dict(intent=w["intent"], approvals=w["approvals"], policy=w["policy"],
                policy_root_key=w["root"].public_key(), keys=w["keys"], receipt=w["receipt"],
                used_nonces=w["nonces"], observed_plaintext_sha256=PLAINTEXT,
                attestation=None, attestation_anchors=[], attestation_nonce="", pcr_policy=None)
    args.update(over)
    return az.verify_authorization(**args)


def test_all_four_elements_pass_and_the_grade_says_what_is_missing(world):
    out = verify(world)                         # executor not attested out of band
    assert out["elements"]["identity"]["grade"] == "CONFIRMED"
    assert out["elements"]["authority"]["grade"] == "CONFIRMED"
    assert out["elements"]["intent"]["grade"] == "CONFIRMED"
    assert out["elements"]["execution"]["grade"] == "HYPOTHESIS"
    assert out["overall"] == "CORROBORATED", "an unverified execution must not round up to CONFIRMED"


def test_execution_is_only_confirmed_by_evidence(world):
    """A fingerprint list used to be enough. Now the quote has to verify, or the claim is refused."""
    out = verify(world, attestation=world["evidence"], attestation_anchors=[world["anchor"]],
                 attestation_nonce=world["nonce"], pcr_policy=world["pcr"])
    assert out["elements"]["execution"]["grade"] == "CONFIRMED", out["elements"]["execution"]["reasons"]
    assert out["overall"] == "CONFIRMED"


def test_a_refused_quote_is_reported_rather_than_raised(world):
    """Found through the CLI: the early-return verdicts had no failed_checks key and the reporting
    path crashed, which is worse than either verdict."""
    for over in ({"attestation_anchors": []},
                 {"attestation_anchors": [world["anchor"]], "pcr_policy": None}):
        args = {"attestation": world["evidence"], "attestation_nonce": world["nonce"]}
        args.update(over)
        out = verify(world, **args)
        assert out["elements"]["execution"]["grade"] == "REFUSED"
        assert out["overall"] == "REFUSED"


def test_evidence_for_another_receipt_is_refused_not_downgraded(world):
    """Presenting evidence that does not hold is a refutation, which is stronger than a gap."""
    elsewhere = _evidence(world["pki"], "ab" * 32)
    out = verify(world, attestation=elsewhere, attestation_anchors=[world["anchor"]],
                 attestation_nonce=world["nonce"], pcr_policy=world["pcr"])
    assert out["elements"]["execution"]["grade"] == "REFUSED"
    assert out["overall"] == "REFUSED"


def test_a_label_is_not_an_identity(world):
    """Relabelling someone else's signature as your own must fail, which is the whole point."""
    forged = replace(world["approvals"][0], approver=az.fingerprint(world["a2"].public_key()))
    out = verify(world, approvals=[forged, world["approvals"][1]])
    assert out["elements"]["identity"]["grade"] == "REFUSED"
    assert any("does not verify" in r for r in out["elements"]["identity"]["reasons"])


def test_requester_cannot_approve_their_own_request(world):
    """Even with the capability granted, the requester's own signature must not count toward quorum."""
    policy = replace(world["policy"], members={
        **world["policy"].members,
        world["intent"].requester: ["request", "approve"],
    }).sign(world["root"])
    self_approval = az.Approval(intent_digest="", approver="").sign(world["req"], world["intent"])
    out = verify(world, policy=policy, approvals=[world["approvals"][0], self_approval])
    assert out["elements"]["authority"]["grade"] == "REFUSED"
    assert any("approved their own request" in r for r in out["elements"]["authority"]["reasons"])


def test_one_approval_is_not_a_quorum(world):
    out = verify(world, approvals=world["approvals"][:1])
    assert out["elements"]["authority"]["grade"] == "REFUSED"
    assert out["elements"]["authority"]["quorum"] == 1
    assert out["elements"]["authority"]["threshold"] == 2


def test_an_approver_without_the_capability_does_not_count(world):
    """a3 can request but not approve; their signature verifies and still must not satisfy quorum."""
    extra = az.Approval(intent_digest="", approver="").sign(world["a3"], world["intent"])
    out = verify(world, approvals=world["approvals"][:1] + [extra])
    assert out["elements"]["identity"]["grade"] == "CONFIRMED"
    assert out["elements"]["authority"]["grade"] == "REFUSED"
    assert any("no approve capability" in r for r in out["elements"]["authority"]["reasons"])


def test_an_expired_request_is_refused(world):
    stale = replace(world["intent"], created_at="2026-01-01T00:00:00Z",
                    expires_at="2026-01-01T01:00:00Z")
    stale = replace(stale, requester_sig="")
    stale = stale.sign(world["req"])
    approvals = [az.Approval(intent_digest="", approver="").sign(k, stale)
                 for k in (world["a1"], world["a2"])]
    out = verify(world, intent=stale, approvals=approvals)
    assert out["elements"]["intent"]["grade"] == "REFUSED"
    assert any("expired" in r for r in out["elements"]["intent"]["reasons"])


def test_a_request_dated_in_the_future_is_refused(world):
    future = _iso(datetime.now(timezone.utc) + timedelta(days=1))
    ahead = replace(world["intent"], created_at=future, expires_at=future, requester_sig="").sign(world["req"])
    approvals = [az.Approval(intent_digest="", approver="").sign(k, ahead) for k in (world["a1"], world["a2"])]
    out = verify(world, intent=ahead, approvals=approvals)
    assert out["elements"]["intent"]["grade"] == "REFUSED"
    assert any("future" in r for r in out["elements"]["intent"]["reasons"])


def test_an_approval_cannot_be_replayed(world):
    world["nonces"].mark(world["intent"].nonce)
    out = verify(world)
    assert out["elements"]["intent"]["grade"] == "REFUSED"
    assert any("already spent" in r for r in out["elements"]["intent"]["reasons"])


def test_an_approval_for_one_object_cannot_unlock_another(world):
    other = replace(world["intent"], object_id="obj-2", requester_sig="").sign(world["req"])
    out = verify(world, intent=other, approvals=world["approvals"])
    assert out["elements"]["intent"]["grade"] == "REFUSED"
    assert any("bound to a different intent" in r for r in out["elements"]["intent"]["reasons"])


def test_a_tampered_policy_fails_even_though_it_parses(world):
    tampered = replace(world["policy"], members={
        **world["policy"].members,
        az.fingerprint(world["a3"].public_key()): ["request", "approve"],
    })
    out = verify(world, policy=tampered)
    assert out["elements"]["authority"]["grade"] == "REFUSED"
    assert any("policy signature does not verify" in r for r in out["elements"]["authority"]["reasons"])


def test_a_request_bound_to_another_policy_revision_is_refused(world):
    out = verify(world, intent=replace(world["intent"], policy_digest="c" * 64))
    assert out["elements"]["authority"]["grade"] == "REFUSED"
    assert any("different policy revision" in r for r in out["elements"]["authority"]["reasons"])


def test_a_receipt_for_a_different_intent_is_refused(world):
    out = verify(world, receipt=replace(world["receipt"], intent_digest="d" * 64))
    assert out["elements"]["execution"]["grade"] == "REFUSED"
    assert out["overall"] == "REFUSED"


def test_the_receipt_must_match_the_bytes_the_verifier_holds(world):
    out = verify(world, observed_plaintext_sha256="e" * 64)
    assert out["elements"]["execution"]["grade"] == "REFUSED"
    assert any("does not match the bytes" in r for r in out["elements"]["execution"]["reasons"])


def test_an_unverified_receipt_is_capped_not_refused(world):
    out = verify(world, observed_plaintext_sha256=None,
                 attestation=world["evidence"], attestation_anchors=[world["anchor"]],
                 attestation_nonce=world["nonce"], pcr_policy=world["pcr"])
    assert out["elements"]["execution"]["grade"] == "HYPOTHESIS", \
        "no bytes to check is unverified, not falsified"


def test_a_missing_receipt_leaves_the_run_incomplete(world):
    out = verify(world, receipt=None)
    assert out["elements"]["execution"]["grade"] == "UNKNOWN"
    assert out["overall"] == "INCOMPLETE"


def test_elements_are_computed_independently(world):
    """A missing requester key must not stop authority, intent or execution from being reported."""
    keys = {k: v for k, v in world["keys"].items() if k != world["intent"].requester}
    out = verify(world, keys=keys)
    assert out["elements"]["identity"]["grade"] == "REFUSED"
    assert out["elements"]["authority"]["grade"] == "CONFIRMED"
    assert out["elements"]["intent"]["grade"] == "CONFIRMED"
    assert out["blocked_by"] == ["identity"]


def test_signatures_are_domain_separated(world):
    """The requester's intent signature must not be usable as an execution receipt."""
    forged = replace(world["receipt"], executor=world["intent"].requester,
                     signature=world["intent"].requester_sig)
    out = verify(world, receipt=forged)
    assert out["elements"]["execution"]["grade"] == "REFUSED"


def test_a_bundle_verifies_from_files_alone(world):
    from cryptography.hazmat.primitives import serialization
    bundle = az.to_bundle(intent=world["intent"], approvals=world["approvals"],
                          policy=world["policy"], receipt=world["receipt"],
                          attestation=world["evidence"])
    out = az.verify_bundle(
        bundle,
        root_public_hex=world["root"].public_key().public_bytes_raw().hex(),
        public_keys={fp: k.public_bytes_raw().hex() for fp, k in world["keys"].items()},
        anchor_pems=[world["anchor"].public_bytes(serialization.Encoding.PEM).decode()],
        attestation_nonce=world["nonce"],
        pcr_policy=world["pcr"].to_dict(),
        observed_plaintext_sha256=PLAINTEXT,
    )
    assert out["overall"] == "CONFIRMED", out["elements"]["execution"]["reasons"]


def test_a_malformed_bundle_is_reported_not_raised(world):
    out = az.verify_bundle({"version": 99}, root_public_hex="00" * 32, public_keys={})
    assert out["overall"] == "MALFORMED"
    assert out["elements"] == {}


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

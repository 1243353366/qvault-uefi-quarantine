"""Execution evidence that can be checked, instead of a fingerprint the verifier is asked to trust.

The earlier version accepted `attested_executors`, a set of fingerprints the verifier had supposedly
learned out of band. That is not evidence: it is the verifier's own assertion, written down. Anyone who
can edit the argument can promote an unattested run to `CONFIRMED`.

What is demanded now, and every one of these is checked rather than reported:

  * an attestation key whose certificate chains to a trust anchor the verifier supplied, not one the
    bundle names;
  * a fresh nonce the verifier chose for this verification, echoed inside the signed statement, so
    evidence recorded once cannot be replayed later;
  * the receipt digest inside the signed statement, so evidence for one execution cannot be moved onto
    another; and
  * a measurement policy - a PCR selection and the digest over those PCRs - so the statement pins a
    platform state, not merely a key. Without it the quote proves only that someone holding a key
    signed a nonce.

What this module does not do: it does not parse TPM2 structures. A real `TPM2_Quote` can be reduced to
this statement by a driver, and the endorsement binding lives in the anchor set, so `CONFIRMED` here
means "signed by a key that traces to an anchor you supplied, over the bytes you hold, under a
measurement policy that matched" and not "this is definitely a TPM". The difference is stated rather
than glossed, and the anchor set is the only thing that can close it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

DOMAIN = b"QVAULT-ATTEST-v1"
FRESHNESS = timedelta(minutes=10)
SKEW = timedelta(seconds=120)
GRADES = ("CONFIRMED", "HYPOTHESIS", "REFUSED")


class AttestationError(ValueError):
    """Malformed evidence. Failures are reported as verdicts, never raised as this."""


def _canon(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _msg(purpose: str, payload: bytes) -> bytes:
    return DOMAIN + b"\x00" + purpose.encode() + b"\x00" + payload


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError(f"not a timestamp: {ts!r}") from exc
    if parsed.tzinfo is None:
        raise AttestationError(f"timestamp has no zone: {ts!r}")
    return parsed


def key_fingerprint(key) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(raw).hexdigest()


def _verify_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> None:
    pub = issuer.public_key()
    if isinstance(pub, ed25519.Ed25519PublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(child.signature_hash_algorithm))
    elif isinstance(pub, rsa.RSAPublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)
    else:  # pragma: no cover - unsupported key type
        raise InvalidSignature(f"unsupported issuer key type {type(pub).__name__}")


# ---------------------------------------------------------------- the measurement policy

@dataclass(frozen=True)
class PcrPolicy:
    """Which registers are quoted, and what they must equal. The verifier's expectation, not the host's."""
    selection: str
    expected_digest: str
    note: str = ""

    def __post_init__(self) -> None:
        if not self.selection or not self.expected_digest:
            raise AttestationError("a measurement policy needs a selection and an expected digest")

    def to_dict(self) -> dict:
        return {"selection": self.selection, "expected_digest": self.expected_digest, "note": self.note}

    @classmethod
    def from_dict(cls, doc) -> "PcrPolicy":
        return cls(selection=doc["selection"], expected_digest=doc["expected_digest"],
                   note=doc.get("note", ""))


# ---------------------------------------------------------------- the statement and its signature

@dataclass(frozen=True)
class AttestationStatement:
    nonce: str                 # chosen by the verifier, echoed here
    receipt_digest: str        # binds this evidence to exactly one execution
    pcr_selection: str
    pcr_digest: str
    ak_name: str               # fingerprint of the attesting key
    generated_at: str = field(default_factory=lambda: _iso(datetime.now(timezone.utc)))

    def payload(self) -> dict:
        return {
            "nonce": self.nonce,
            "receipt_digest": self.receipt_digest,
            "pcr_selection": self.pcr_selection,
            "pcr_digest": self.pcr_digest,
            "ak_name": self.ak_name,
            "generated_at": self.generated_at,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_msg("statement", _canon(self.payload()))).hexdigest()


@dataclass(frozen=True)
class AttestationEvidence:
    statement: AttestationStatement
    chain_pem: Sequence[str]   # leaf (attestation key) first, issuers after
    signature: str = ""

    def payload(self) -> dict:
        return {"statement": self.statement.payload(), "chain_pem": list(self.chain_pem)}

    def sign(self, ak_private) -> "AttestationEvidence":
        message = _msg("quote", _canon(self.statement.payload()))
        # An attestation key is whatever the endorsement CA issued: EC, RSA or Ed25519.
        if isinstance(ak_private, ed25519.Ed25519PrivateKey):
            signature = ak_private.sign(message)
        elif isinstance(ak_private, ec.EllipticCurvePrivateKey):
            signature = ak_private.sign(message, ec.ECDSA(hashes.SHA256()))
        else:
            signature = ak_private.sign(message, padding.PKCS1v15(), hashes.SHA256())
        return replace(self, signature=signature.hex())

    def to_dict(self) -> dict:
        return {**self.payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, doc) -> "AttestationEvidence":
        return cls(statement=AttestationStatement(**doc["statement"]),
                   chain_pem=list(doc.get("chain_pem") or []),
                   signature=doc.get("signature", ""))


# ---------------------------------------------------------------- verification

def verify_attestation(
    evidence: AttestationEvidence | None,
    *,
    receipt_digest: str,
    expected_nonce: str,
    anchors: Sequence[x509.Certificate],
    pcr_policy: PcrPolicy | None,
    now: datetime | None = None,
) -> dict:
    """Every requirement is checked; nothing is taken on the bundle's word."""
    moment = now or datetime.now(timezone.utc)
    reasons: list[str] = []
    fail = []                      # each entry is a check that did not hold

    if evidence is None:
        return {"grade": "HYPOTHESIS", "ok": False, "ak_name": None, "failed_checks": [],
                "reasons": ["no attestation evidence presented: the receipt is the host's own claim"]}
    if not anchors:
        return {"grade": "REFUSED", "ok": False, "ak_name": None,
                "failed_checks": ["no trust anchor supplied"],
                "reasons": ["no trust anchor supplied: nothing exists to check the chain against"]}
    if pcr_policy is None:
        return {"grade": "REFUSED", "ok": False, "ak_name": None,
                "failed_checks": ["no measurement policy"],
                "reasons": ["no measurement policy: a bare quote pins a key, not a platform state"]}

    # ---- chain
    certs: list[x509.Certificate] = []
    for pem in evidence.chain_pem:
        try:
            certs.append(x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem))
        except ValueError as exc:
            fail.append(f"certificate could not be parsed: {exc}")
    if not certs:
        fail.append("the bundle carried no certificate chain")

    if certs:
        for position, cert in enumerate(certs):
            try:
                before, after = cert.not_valid_before_utc, cert.not_valid_after_utc
            except AttributeError:  # pragma: no cover - older cryptography
                before, after = cert.not_valid_before, cert.not_valid_after
            if not (before <= moment <= after):
                fail.append(f"certificate {cert.subject.rfc4514_string()} is outside its validity window")
            try:
                basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            except x509.ExtensionNotFound:
                basic = None
            if position == 0 and basic is not None and basic.ca:
                fail.append("the leaf presented as an attestation key is a CA certificate")
            if position > 0 and (basic is None or not basic.ca):
                fail.append(f"issuer {cert.subject.rfc4514_string()} is not marked as a CA")

        for child, issuer in zip(certs, certs[1:]):
            try:
                _verify_signed_by(child, issuer)
            except (InvalidSignature, ValueError):
                fail.append(f"{child.subject.rfc4514_string()} is not signed by "
                            f"{issuer.subject.rfc4514_string()}")

        last = certs[-1]
        anchored = any(a.fingerprint(hashes.SHA256()) == last.fingerprint(hashes.SHA256())
                       for a in anchors)
        if not anchored:
            for anchor in anchors:
                try:
                    _verify_signed_by(last, anchor)
                    anchored = True
                    break
                except (InvalidSignature, ValueError):
                    continue
        if not anchored:
            fail.append("the chain does not terminate at any supplied trust anchor")

    # ---- binding, freshness, measurement
    statement = evidence.statement
    if statement.receipt_digest != receipt_digest:
        fail.append("the statement attests a different receipt")
    else:
        reasons.append("statement is bound to this receipt")
    if statement.nonce != expected_nonce:
        fail.append("the nonce is not the one this verifier issued: the evidence is replayed or stale")
    else:
        reasons.append("nonce matches the one this verifier issued")
    try:
        generated = _parse(statement.generated_at)
        if abs(moment - generated) > FRESHNESS:
            fail.append(f"statement is outside the freshness window: generated {statement.generated_at}")
    except AttestationError as exc:
        fail.append(str(exc))
    if statement.pcr_selection != pcr_policy.selection:
        fail.append(f"measurement selection {statement.pcr_selection!r} does not match the policy")
    if statement.pcr_digest != pcr_policy.expected_digest:
        fail.append("measured PCR digest does not match the policy expectation")
    if not any("measurement selection" in f for f in fail) and \
            not any("PCR digest" in f for f in fail):
        reasons.append(f"measurements match the policy ({pcr_policy.selection})")

    # ---- the quote signature, with the key the chain actually yielded
    ak_name = None
    if certs:
        ak_key = certs[0].public_key()
        ak_name = key_fingerprint(ak_key)
        if statement.ak_name != ak_name:
            fail.append("statement names an attesting key that is not the one in the chain")
        if not evidence.signature:
            fail.append("quote is unsigned")
        else:
            try:
                if isinstance(ak_key, ed25519.Ed25519PublicKey):
                    ak_key.verify(bytes.fromhex(evidence.signature),
                                  _msg("quote", _canon(statement.payload())))
                elif isinstance(ak_key, ec.EllipticCurvePublicKey):
                    ak_key.verify(bytes.fromhex(evidence.signature),
                                  _msg("quote", _canon(statement.payload())),
                                  ec.ECDSA(hashes.SHA256()))
                else:
                    ak_key.verify(bytes.fromhex(evidence.signature),
                                  _msg("quote", _canon(statement.payload())),
                                  padding.PKCS1v15(), hashes.SHA256())
                reasons.append("quote signature verifies against the attested key")
            except (InvalidSignature, ValueError):
                fail.append("quote signature does not verify")

    ok = not fail
    return {
        "grade": "CONFIRMED" if ok else "REFUSED",
        "ok": ok,
        "ak_name": ak_name,
        "reasons": reasons + fail,
        "failed_checks": fail,
    }

"""Authorization as four separately verifiable elements, not one name comparison.

The problem this answers: an approval recorded as the string `--approver reviewer2` proves nothing.
Anyone who can run the CLI can type that name, and an action taken by a compromised workstation is
indistinguishable in the record from one taken by its operator. So authority is split into four
questions that each carry their own evidence and are each checked on their own:

  identity    who is asking, and who approved. Bound to a signing key, never to a label. A name is
              carried only as a human-readable annotation on a fingerprint.
  authority   whether that key is permitted, according to a policy document signed by a root key, and
              separately whether it holds the capability this request needs.
  intent      what exactly was approved: object id, ciphertext hash, purpose, expiry and a single-use
              nonce, all inside the signed bytes. An approval for one object cannot be replayed for
              another, and an approval is not a reusable capability.
  execution   what actually happened, checked against the artefact rather than the host's own account
              of itself. The verifier hashes the bytes it received and requires the receipt to name
              that hash.

Each element is computed independently and none short-circuits the others, because an early return
hides which element failed and lets a broken authority check masquerade as a broken identity.

Grades follow the project's vocabulary. Identity, authority and intent reach CONFIRMED when their
signatures verify. Execution reaches CONFIRMED only against `qvault/attestation.py`: a quote over this
receipt's digest, under a PCR policy the verifier supplied, carrying a nonce the verifier issued, signed
by a key that chains to an anchor. A fingerprint allowlist used to pass for that, which was the
verifier asserting its own conclusion; evidence that is offered and does not hold is now a REFUSED
rather than a downgrade.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

if TYPE_CHECKING:  # annotations are strings here; these names are never resolved at runtime
    from .attestation import AttestationEvidence, PcrPolicy

DOMAIN = b"QVAULT-AUTHZ-v1"
ELEMENTS = ("identity", "authority", "intent", "execution")
SKEW = timedelta(seconds=60)


class AuthorizationError(ValueError):
    """Malformed authorization material. Never raised for a failed check: failures are reported."""


def _canon(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _msg(purpose: str, payload: bytes) -> bytes:
    """Domain-separated. An intent signature must not be replayable as a policy or receipt signature."""
    return DOMAIN + b"\x00" + purpose.encode() + b"\x00" + payload


def fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def load_public(raw_hex: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(raw_hex))


def _now(now: datetime | None) -> datetime:
    return now or datetime.now(timezone.utc)


def _parse(ts: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError(f"not a timestamp: {ts!r}") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"timestamp has no zone: {ts!r}")
    return parsed


def _is_sha256(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- intent

@dataclass(frozen=True)
class Intent:
    """What is being asked for. The requester signs it, so the request is attributable, not merely stated."""
    object_id: str
    ciphertext_sha256: str
    purpose: str
    requester: str
    policy_digest: str
    threshold: int
    nonce: str = field(default_factory=lambda: secrets.token_hex(32))
    created_at: str = field(default_factory=lambda: _iso(datetime.now(timezone.utc)))
    expires_at: str = ""
    requester_sig: str = ""

    def __post_init__(self) -> None:
        if not _is_sha256(self.ciphertext_sha256):
            raise AuthorizationError("ciphertext_sha256 must be lowercase sha256 hex")
        if self.purpose not in ("decrypt", "export", "analyse"):
            raise AuthorizationError(f"unknown purpose {self.purpose!r}")
        if self.threshold < 1:
            raise AuthorizationError("threshold must be at least 1")
        if not self.expires_at:
            object.__setattr__(self, "expires_at", _iso(datetime.now(timezone.utc) + timedelta(hours=1)))

    def payload(self) -> dict:
        return {
            "object_id": self.object_id,
            "ciphertext_sha256": self.ciphertext_sha256,
            "purpose": self.purpose,
            "requester": self.requester,
            "policy_digest": self.policy_digest,
            "threshold": self.threshold,
            "nonce": self.nonce,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

    @property
    def digest(self) -> str:
        """Approvers sign this digest, so their signature covers the object, purpose and expiry."""
        return hashlib.sha256(_msg("intent", _canon(self.payload()))).hexdigest()

    def sign(self, private: Ed25519PrivateKey) -> "Intent":
        # The fingerprint must be in the payload before it is signed. Signing first and binding the
        # key afterwards produces a request that cannot verify against itself.
        draft = replace(self, requester=fingerprint(private.public_key()), requester_sig="")
        sig = private.sign(_msg("intent-request", _canon(draft.payload())))
        return replace(draft, requester_sig=sig.hex())

    def to_dict(self) -> dict:
        return {**self.payload(), "requester_sig": self.requester_sig}

    @classmethod
    def from_dict(cls, doc: Mapping) -> "Intent":
        return cls(**{k: doc[k] for k in (
            "object_id", "ciphertext_sha256", "purpose", "requester", "policy_digest",
            "threshold", "nonce", "created_at", "expires_at")}, requester_sig=doc.get("requester_sig", ""))


# ---------------------------------------------------------------- authority

@dataclass(frozen=True)
class AuthorityPolicy:
    """Who may ask and who may approve. Signed by a root key that never signs an approval itself."""
    members: Mapping[str, Sequence[str]]
    threshold: int = 2
    issued_at: str = field(default_factory=lambda: _iso(datetime.now(timezone.utc)))
    valid_until: str = ""
    root: str = ""
    signature: str = ""

    def payload(self) -> dict:
        return {
            "members": {k: sorted(v) for k, v in sorted(self.members.items())},
            "threshold": self.threshold,
            "issued_at": self.issued_at,
            "valid_until": self.valid_until,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_msg("policy", _canon(self.payload()))).hexdigest()

    def caps(self, who: str) -> set[str]:
        return set(self.members.get(who, ()))

    def sign(self, root_private: Ed25519PrivateKey) -> "AuthorityPolicy":
        sig = root_private.sign(_msg("policy", _canon(self.payload())))
        return replace(self, root=fingerprint(root_private.public_key()), signature=sig.hex())

    def to_dict(self) -> dict:
        return {**self.payload(), "root": self.root, "signature": self.signature}

    @classmethod
    def from_dict(cls, doc: Mapping) -> "AuthorityPolicy":
        return cls(members={k: list(v) for k, v in doc.get("members", {}).items()},
                   threshold=int(doc.get("threshold", 2)), issued_at=doc.get("issued_at", ""),
                   valid_until=doc.get("valid_until", ""), root=doc.get("root", ""),
                   signature=doc.get("signature", ""))

    def verify(self, root_key: Ed25519PublicKey) -> bool:
        if not self.signature or self.root != fingerprint(root_key):
            return False
        try:
            root_key.verify(bytes.fromhex(self.signature), _msg("policy", _canon(self.payload())))
            return True
        except (InvalidSignature, ValueError):
            return False


# ---------------------------------------------------------------- approval

@dataclass(frozen=True)
class Approval:
    """One approver's signature over one intent digest. Not transferable to another intent."""
    intent_digest: str
    approver: str
    signed_at: str = field(default_factory=lambda: _iso(datetime.now(timezone.utc)))
    signature: str = ""

    def payload(self) -> dict:
        return {"intent_digest": self.intent_digest, "approver": self.approver, "signed_at": self.signed_at}

    def sign(self, private: Ed25519PrivateKey, intent: Intent) -> "Approval":
        draft = replace(self, intent_digest=intent.digest, approver=fingerprint(private.public_key()))
        return replace(draft, signature=private.sign(_msg("approval", _canon(draft.payload()))).hex())

    def verify(self, key: Ed25519PublicKey) -> bool:
        if self.approver != fingerprint(key) or not self.signature:
            return False
        try:
            key.verify(bytes.fromhex(self.signature), _msg("approval", _canon(self.payload())))
            return True
        except (InvalidSignature, ValueError):
            return False

    def to_dict(self) -> dict:
        return {**self.payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, doc: Mapping) -> "Approval":
        return cls(intent_digest=doc["intent_digest"], approver=doc["approver"],
                   signed_at=doc.get("signed_at", ""), signature=doc.get("signature", ""))


# ---------------------------------------------------------------- execution

@dataclass(frozen=True)
class Receipt:
    """What the executor claims happened, bound to the intent and to the bytes that were produced."""
    intent_digest: str
    object_id: str
    plaintext_sha256: str
    executor: str
    attestation: str = "none"
    produced_at: str = field(default_factory=lambda: _iso(datetime.now(timezone.utc)))
    signature: str = ""

    def payload(self) -> dict:
        return {
            "intent_digest": self.intent_digest,
            "object_id": self.object_id,
            "plaintext_sha256": self.plaintext_sha256,
            "executor": self.executor,
            "attestation": self.attestation,
            "produced_at": self.produced_at,
        }

    @property
    def digest(self) -> str:
        """What attestation evidence binds to, so a quote cannot be moved between executions."""
        return hashlib.sha256(_msg("receipt", _canon(self.payload()))).hexdigest()

    def sign(self, private: Ed25519PrivateKey) -> "Receipt":
        draft = replace(self, executor=fingerprint(private.public_key()))
        return replace(draft, signature=private.sign(_msg("receipt", _canon(draft.payload()))).hex())

    def verify(self, key: Ed25519PublicKey) -> bool:
        if self.executor != fingerprint(key) or not self.signature:
            return False
        try:
            key.verify(bytes.fromhex(self.signature), _msg("receipt", _canon(self.payload())))
            return True
        except (InvalidSignature, ValueError):
            return False

    def to_dict(self) -> dict:
        return {**self.payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, doc: Mapping) -> "Receipt":
        return cls(intent_digest=doc["intent_digest"], object_id=doc["object_id"],
                   plaintext_sha256=doc["plaintext_sha256"], executor=doc["executor"],
                   attestation=doc.get("attestation", "none"),
                   produced_at=doc.get("produced_at", ""), signature=doc.get("signature", ""))


# ---------------------------------------------------------------- nonce store

class NonceStore:
    """Single-use nonces. A file of hex digests, append-only; replay is a lookup, not an inference."""

    def __init__(self, path: str):
        self.path = path

    def seen(self, nonce: str) -> bool:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return any(line.strip() == nonce for line in fh)
        except FileNotFoundError:
            return False

    def mark(self, nonce: str) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(nonce + "\n")


# ---------------------------------------------------------------- the four verdicts

def _verdict(grade: str, reasons: Sequence[str], **extra) -> dict:
    return {"grade": grade, "ok": grade != "REFUSED", "reasons": list(reasons), **extra}


def verify_authorization(
    *,
    intent: Intent,
    approvals: Iterable[Approval],
    policy: AuthorityPolicy,
    policy_root_key: Ed25519PublicKey,
    keys: Mapping[str, Ed25519PublicKey],
    receipt: Receipt | None = None,
    used_nonces: NonceStore | None = None,
    attestation: "AttestationEvidence | None" = None,
    attestation_anchors: Sequence = (),
    attestation_nonce: str = "",
    pcr_policy: "PcrPolicy | None" = None,
    observed_plaintext_sha256: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Check all four elements. None short-circuits, so a failure in one cannot hide another."""
    moment = _now(now)
    approvals = list(approvals)
    verdicts: dict[str, dict] = {}

    # ---- identity: signatures, not labels
    reasons: list[str] = []
    verified: list[str] = []
    requester_key = keys.get(intent.requester)
    requester_ok = False
    if requester_key is None:
        reasons.append("requester key is not in the verifier's key set")
    elif not intent.requester_sig:
        reasons.append("request is unsigned")
    else:
        try:
            requester_key.verify(bytes.fromhex(intent.requester_sig),
                                 _msg("intent-request", _canon(intent.payload())))
            requester_ok = True
            reasons.append(f"requester {intent.requester[:16]} signature verified")
        except (InvalidSignature, ValueError):
            reasons.append("requester signature does not verify")
    for approval in approvals:
        key = keys.get(approval.approver)
        if key is None:
            reasons.append(f"approver key {approval.approver[:16]} is not in the verifier's key set")
        elif approval.verify(key):
            verified.append(approval.approver)
            reasons.append(f"approver {approval.approver[:16]} signature verified")
        else:
            reasons.append(f"approver {approval.approver[:16]} signature does not verify")
    if not approvals:
        reasons.append("no approvals presented")
    identity_ok = requester_ok and bool(verified) and len(verified) == len(approvals)
    verdicts["identity"] = _verdict("CONFIRMED" if identity_ok else "REFUSED", reasons,
                                    verified_signers=sorted(set(verified)))

    # ---- authority: signed policy, capability, quorum, separation of duties
    reasons = []
    policy_sig_ok = policy.verify(policy_root_key)
    reasons.append("policy signature verified" if policy_sig_ok
                   else "policy signature does not verify against the root key")
    try:
        if policy.valid_until and _parse(policy.valid_until) < moment:
            reasons.append(f"policy expired at {policy.valid_until}")
            policy_sig_ok = False
    except AuthorizationError as exc:
        reasons.append(str(exc))
        policy_sig_ok = False
    bound = intent.policy_digest == policy.digest
    reasons.append("request names this policy revision" if bound
                   else "request was made under a different policy revision")
    requester_allowed = "request" in policy.caps(intent.requester)
    reasons.append("requester holds the request capability" if requester_allowed
                   else "requester does not hold the request capability")
    entitled = [a for a in verified if "approve" in policy.caps(a)]
    for a in verified:
        if a not in entitled:
            reasons.append(f"approver {a[:16]} verified but holds no approve capability")
    threshold = max(intent.threshold, policy.threshold)
    quorum = len(set(entitled))
    reasons.append(f"{quorum} entitled approval(s), threshold {threshold}")
    distinct = intent.requester not in entitled
    reasons.append("requester is not among the approvers" if distinct
                   else "requester approved their own request")
    authority_ok = policy_sig_ok and bound and requester_allowed and quorum >= threshold and distinct
    verdicts["authority"] = _verdict("CONFIRMED" if authority_ok else "REFUSED", reasons,
                                     quorum=quorum, threshold=threshold)

    # ---- intent: what exactly was approved, and is it still the same thing
    reasons = []
    try:
        created, expires = _parse(intent.created_at), _parse(intent.expires_at)
        if created > moment + SKEW:
            reasons.append(f"request dated in the future: {intent.created_at}")
        if expires < moment:
            reasons.append(f"request expired at {intent.expires_at}")
        if expires <= created:
            reasons.append("request expires before it was created")
        window_ok = not any(r.startswith(("request dated", "request expired", "request expires"))
                            for r in reasons)
    except AuthorizationError as exc:
        reasons.append(str(exc))
        window_ok = False
    mismatched = [a.approver for a in approvals if a.intent_digest != intent.digest]
    for who in mismatched:
        reasons.append(f"approval from {who[:16]} is bound to a different intent")
    reasons.append("every approval is bound to this intent" if not mismatched
                   else f"{len(mismatched)} approval(s) bind another intent")
    replay = bool(used_nonces and used_nonces.seen(intent.nonce))
    reasons.append("nonce has not been used before" if not replay
                   else "nonce was already spent: this approval is a replay")
    object_ok = bool(intent.object_id) and _is_sha256(intent.ciphertext_sha256)
    reasons.append("object and ciphertext hash are well formed" if object_ok
                   else "object id or ciphertext hash is malformed")
    intent_ok = window_ok and not mismatched and not replay and object_ok
    verdicts["intent"] = _verdict("CONFIRMED" if intent_ok else "REFUSED", reasons,
                                  intent_digest=intent.digest)

    # ---- execution: the artefact, not the host's word for it
    reasons = []
    if receipt is None:
        verdicts["execution"] = _verdict("UNKNOWN", ["no execution receipt presented"])
    else:
        exec_key = keys.get(receipt.executor)
        sig_ok = bool(exec_key) and receipt.verify(exec_key)
        reasons.append("receipt signature verified" if sig_ok
                       else "receipt signature does not verify")
        bound_intent = receipt.intent_digest == intent.digest
        reasons.append("receipt names this intent" if bound_intent
                       else "receipt names a different intent")
        bound_object = receipt.object_id == intent.object_id
        reasons.append("receipt names this object" if bound_object
                       else "receipt names a different object")
        well_formed = _is_sha256(receipt.plaintext_sha256)
        # "Not checked" and "contradicted" are different findings and must not collapse into one.
        # Without the bytes the claim is unverified, which caps the grade; only a mismatch refutes it.
        contradicted = False
        if observed_plaintext_sha256 is not None:
            if observed_plaintext_sha256 == receipt.plaintext_sha256:
                reasons.append("receipt hash matches the bytes the verifier received")
            else:
                reasons.append("receipt hash does not match the bytes the verifier received")
                contradicted = True
        else:
            reasons.append("no observed plaintext hash supplied: the receipt is the only account")
        ok = sig_ok and bound_intent and bound_object and well_formed and not contradicted
        if not ok:
            verdicts["execution"] = _verdict("REFUSED", reasons)
        elif observed_plaintext_sha256 is None:
            verdicts["execution"] = _verdict(
                "HYPOTHESIS", reasons + ["no bytes to check: the receipt is unverified, not falsified"])
        else:
            # A fingerprint list is not evidence. What is demanded is a quote over this receipt, under a
            # measurement policy, with a nonce this verifier issued, from a key that chains to an anchor.
            from .attestation import verify_attestation
            quote = verify_attestation(
                attestation,
                receipt_digest=receipt.digest,
                expected_nonce=attestation_nonce,
                anchors=list(attestation_anchors),
                pcr_policy=pcr_policy,
                now=moment,
            )
            reasons.extend(f"attestation: {r}" for r in quote["reasons"])
            if quote["grade"] == "CONFIRMED":
                verdicts["execution"] = _verdict("CONFIRMED", reasons, ak_name=quote["ak_name"])
            elif attestation is None and not attestation_anchors and not attestation_nonce:
                verdicts["execution"] = _verdict("HYPOTHESIS", reasons)
            else:
                # Evidence was presented and did not hold. That is a refutation, not a gap.
                verdicts["execution"] = _verdict("REFUSED", reasons,
                                                 failed_checks=quote.get("failed_checks", []))

    # A contradicted execution is a refusal like any other: the receipt named bytes that were not the
    # bytes. Only "not yet checked" is allowed to leave the run merely incomplete.
    blocked = [name for name in ELEMENTS if verdicts[name]["grade"] == "REFUSED"]
    if blocked:
        overall = "REFUSED"
    elif verdicts["execution"]["grade"] == "CONFIRMED":
        overall = "CONFIRMED"
    elif verdicts["execution"]["grade"] == "HYPOTHESIS":
        overall = "CORROBORATED"
    else:
        overall = "INCOMPLETE"
    return {"overall": overall, "blocked_by": blocked, "elements": verdicts}


# ---------------------------------------------------------------- offline bundle

def to_bundle(*, intent: Intent, approvals: Iterable[Approval], policy: AuthorityPolicy,
              receipt: Receipt | None = None, attestation=None) -> dict:
    return {
        "version": 1,
        "intent": intent.to_dict(),
        "approvals": [a.to_dict() for a in approvals],
        "policy": policy.to_dict(),
        "receipt": receipt.to_dict() if receipt else None,
        "attestation": attestation.to_dict() if attestation else None,
    }


def verify_bundle(bundle: Mapping, *,
                  root_public_hex: str,
                  public_keys: Mapping[str, str],
                  anchor_pems: Sequence[str] = (),
                  attestation_nonce: str = "",
                  pcr_policy: Mapping | None = None,
                  observed_plaintext_sha256: str | None = None,
                  used_nonces: NonceStore | None = None,
                  now: datetime | None = None) -> dict:
    """Verify from files alone: no vault, no host state, no trust in the machine that produced them."""
    try:
        if bundle.get("version") != 1:
            raise AuthorizationError(f"unsupported bundle version {bundle.get('version')!r}")
        intent = Intent.from_dict(bundle["intent"])
        policy = AuthorityPolicy.from_dict(bundle["policy"])
        approvals = [Approval.from_dict(d) for d in bundle.get("approvals") or []]
        receipt = Receipt.from_dict(bundle["receipt"]) if bundle.get("receipt") else None
        keys = {fp: load_public(raw) for fp, raw in public_keys.items()}
        root = load_public(root_public_hex)
        from .attestation import AttestationEvidence, PcrPolicy
        from cryptography import x509
        evidence = (AttestationEvidence.from_dict(bundle["attestation"])
                    if bundle.get("attestation") else None)
        anchors = [x509.load_pem_x509_certificate(pem.encode()) for pem in anchor_pems]
        policy_pcr = PcrPolicy.from_dict(pcr_policy) if pcr_policy else None
    except (KeyError, TypeError, AuthorizationError, ValueError) as exc:
        return {"overall": "MALFORMED", "blocked_by": list(ELEMENTS), "error": str(exc), "elements": {}}
    return verify_authorization(intent=intent, approvals=approvals, policy=policy,
                                policy_root_key=root, keys=keys, receipt=receipt,
                                used_nonces=used_nonces, attestation=evidence,
                                attestation_anchors=anchors, attestation_nonce=attestation_nonce,
                                pcr_policy=policy_pcr,
                                observed_plaintext_sha256=observed_plaintext_sha256, now=now)

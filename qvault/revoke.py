"""
qvault.revoke
=============

Credential revocation, with the ordering and the limits made explicit.

Why this is not a checkbox
--------------------------
"Rotate the credentials" is the advice every incident report ends with, and it is
usually wrong in three specific ways:

1. **Wrong order.** Revoking an access token while a refresh token survives
   accomplishes nothing: the attacker mints a new access token in seconds. Credentials
   that *create* credentials must die first.
2. **Wrong meaning.** Deleting a key file, clearing a browser session or resetting a
   local password is not revocation. Revocation is a fact about the *issuer*: the
   credential no longer authenticates. Anything less is housekeeping.
3. **Wrong claim.** Some credentials cannot be revoked at all: embedded device
   credentials, shared secrets with no rotation path, certificates with no CRL or OCSP
   distribution point. These need replacement or a compensating control, and calling
   them "revoked" is a false statement in a report someone will rely on.

And the limit underneath all of it: revocation stops *future* use of a credential. It
does not remove copies already taken, does not expire what the attacker already holds,
and does not remove the implant that took them. Revocation is containment, never
eradication.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- credential kinds -----------------------------------------------------

SESSION_TOKEN = "session_token"
REFRESH_TOKEN = "refresh_token"
OAUTH_GRANT = "oauth_grant"
API_KEY = "api_key"
SSH_KEY = "ssh_key"
CERT = "cert"
DEVICE_CERT = "device_cert"
PASSWORD = "password"
SHARED_SECRET = "shared_secret"

KINDS = (SESSION_TOKEN, REFRESH_TOKEN, OAUTH_GRANT, API_KEY, SSH_KEY, CERT,
         DEVICE_CERT, PASSWORD, SHARED_SECRET)

# Revocation order. Lower dies first.
#  0 mints other credentials (a surviving refresh token undoes everything above it)
#  1 short-lived online sessions
#  2 interactive/API secrets
#  3 long-lived asymmetric material (keys, certificates)
#  4 shared secrets that require coordinated rotation at every consumer
TIER = {
    REFRESH_TOKEN: 0,
    OAUTH_GRANT: 0,
    SESSION_TOKEN: 1,
    API_KEY: 2,
    PASSWORD: 2,
    SSH_KEY: 3,
    CERT: 3,
    DEVICE_CERT: 3,
    SHARED_SECRET: 4,
}

# Credentials that authenticate without reaching the issuer, so a revocation performed
# "online" may not reach the copy the attacker holds.
OFFLINE_CAPABLE = frozenset({API_KEY, SSH_KEY, CERT, DEVICE_CERT, PASSWORD, SHARED_SECRET})

VERIFICATION = {
    SESSION_TOKEN: "issuer introspection reports the token inactive; the session is gone",
    REFRESH_TOKEN: "issuer reports the grant revoked; a refresh attempt is refused",
    OAUTH_GRANT: "the application's grant is removed at the issuer; consent list no longer shows it",
    API_KEY: "the key is absent from the issuer's key list and a test call returns 401",
    SSH_KEY: "the public key is absent from every authorized_keys target and login fails",
    CERT: "CRL or OCSP reports the serial revoked and a handshake is refused",
    DEVICE_CERT: "the device certificate is rejected by the authenticating service",
    PASSWORD: "authentication fails and all existing sessions for the account are invalidated",
    SHARED_SECRET: "the secret is rotated at every consumer and the old value is rejected",
}

COMPENSATION = {
    SESSION_TOKEN: "expire by timeout; low residual risk",
    REFRESH_TOKEN: "revoke at the issuer; a client-side delete does not help",
    OAUTH_GRANT: "remove the grant at the issuer, then re-consent deliberately",
    API_KEY: "rotate and narrow the scope of the replacement",
    SSH_KEY: "rotate the key pair and pin the new public key on every target",
    CERT: "reissue with a new key; treat the old private key as disclosed",
    DEVICE_CERT: "device replacement, or re-provisioning with a new identity",
    PASSWORD: "rotate, invalidate sessions, and require a second factor",
    SHARED_SECRET: "coordinate rotation across every consumer, then verify each",
}


class RevocationError(ValueError):
    """Raised when a revocation plan would not actually revoke anything."""


@dataclass(frozen=True)
class Credential:
    identifier: str
    kind: str
    scope: str = ""
    host: str = ""
    has_revocation_channel: bool = True

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise RevocationError(f"unknown credential kind {self.kind!r}; known: {KINDS}")
        if not self.identifier.strip():
            raise RevocationError("a credential needs an identifier")

    @property
    def offline_capable(self) -> bool:
        return self.kind in OFFLINE_CAPABLE

    @property
    def tier(self) -> int:
        return TIER[self.kind]

    @property
    def revocable(self) -> bool:
        """Whether the issuer can actually refuse this credential."""
        return self.has_revocation_channel


@dataclass(frozen=True)
class Step:
    order: int
    identifier: str
    kind: str
    action: str
    verification: str
    why: str
    compensation: str
    revocable: bool


@dataclass
class Record:
    """What actually happened, which is not the same as what was planned."""

    step: Step
    status: str = "requested"   # requested | confirmed | failed | unverifiable

    STATUSES = ("requested", "confirmed", "failed", "unverifiable")

    def __post_init__(self) -> None:
        if self.status not in self.STATUSES:
            raise RevocationError(f"unknown status {self.status!r}")

    @property
    def revoked(self) -> bool:
        """Only issuer confirmation counts. Requested is not revoked."""
        return self.status == "confirmed"


def plan_revocation(
    credentials,
    *,
    compromised_host: str = "",
    revoking_from_host: str = "",
    inventory_complete: bool = True,
) -> dict:
    """Ordered revocation steps, unrevocable material, and the gaps."""
    credentials = sorted(credentials, key=lambda c: (c.tier, c.identifier))
    if not credentials:
        raise RevocationError("no credentials supplied: an empty plan revokes nothing")

    warnings: list[str] = []
    if compromised_host and revoking_from_host and revoking_from_host == compromised_host:
        warnings.append(
            f"revocation is being driven from {revoking_from_host}, the host believed "
            "compromised: the attacker can observe each step and use each credential "
            "before it dies. Revoke from a host outside the blast radius."
        )

    steps: list[Step] = []
    unrevocable: list[Step] = []
    for order, cred in enumerate(credentials, start=1):
        action = (
            f"revoke {cred.kind} {cred.identifier} at the issuer"
            if cred.revocable else
            f"{cred.kind} {cred.identifier} has no revocation channel: replace or rotate it"
        )
        why = (
            "first: it mints other credentials, so anything revoked before it is undone"
            if cred.tier == 0 else
            "shared secret: rotation must be coordinated across every consumer, so it "
            "goes last" if cred.tier == 4 else
            "long-lived asymmetric material: usable offline, so issuer revocation alone "
            "may not reach the attacker's copy"
            if cred.kind in (SSH_KEY, CERT, DEVICE_CERT) else
            "usable without reaching the issuer, so a revocation online may not reach the "
            "copy the attacker holds" if cred.offline_capable else
            "authenticates against the issuer, so revocation is decisive"
        )
        step = Step(order=order, identifier=cred.identifier, kind=cred.kind, action=action,
                    verification=VERIFICATION[cred.kind], why=why,
                    compensation=COMPENSATION[cred.kind], revocable=cred.revocable)
        (steps if cred.revocable else unrevocable).append(step)

    gaps: list[str] = []
    if not inventory_complete:
        gaps.append(
            "credential inventory may be incomplete: nothing can revoke a credential "
            "nobody enumerated, and absence from the inventory is not absence of the credential"
        )
    offline_survivors = [s.identifier for s in steps if s.kind in OFFLINE_CAPABLE]
    if offline_survivors:
        gaps.append(
            f"{len(offline_survivors)} offline-capable credential(s) are usable without "
            "touching the issuer; confirm the attacker's copies are expired, not just revoked"
        )

    return {
        "steps": steps,
        "unrevocable": unrevocable,
        "gaps": gaps,
        "warnings": warnings,
        "safe_to_proceed": not warnings,
        "statement": (
            f"{len(steps)} credential(s) to revoke, {len(unrevocable)} that cannot be "
            "revoked and need replacement. Revocation stops future use; it does not "
            "recover what was already taken."
            if steps else
            f"no revocable credentials in the inventory: {len(unrevocable)} credential(s) "
            "cannot be revoked and need replacement, which is a different procedure"
        ),
    }


def verify(records) -> dict:
    """Whether the plan actually revoked anything, per issuer confirmation."""
    records = list(records)
    confirmed = [r for r in records if r.revoked]
    pending = [r for r in records if r.status == "requested"]
    failed = [r for r in records if r.status == "failed"]
    unverifiable = [r for r in records if r.status == "unverifiable"]

    still_usable = [
        r.step.identifier for r in records
        if not r.revoked and r.step.kind in OFFLINE_CAPABLE
    ]

    if failed or unverifiable:
        verdict = "incomplete"
    elif pending:
        verdict = "requested_only"
    elif still_usable:
        verdict = "incomplete"
    else:
        verdict = "revoked"

    return {
        "verdict": verdict,
        "confirmed": len(confirmed),
        "pending": [r.step.identifier for r in pending],
        "failed": [r.step.identifier for r in failed],
        "unverifiable": [r.step.identifier for r in unverifiable],
        "still_usable": still_usable,
        "statement": {
            "revoked": f"{len(confirmed)} credential(s) confirmed revoked at the issuer.",
            "requested_only": (
                f"{len(pending)} revocation(s) requested but not confirmed. A request is "
                "not a revocation: confirm at the issuer."
            ),
            "incomplete": (
                f"{len(failed) + len(unverifiable)} credential(s) unconfirmed and "
                f"{len(still_usable)} usable offline. Treat them as still valid."
            ),
        }[verdict],
    }


def limits() -> list[str]:
    """What revocation cannot do, stated where a reader will find it."""
    return [
        "revocation stops future use; copies already exfiltrated remain valid until expiry",
        "it does not remove the implant, the backdoor or the persistence that took the credential",
        "it cannot cover credentials that were never enumerated",
        "some credentials have no revocation channel and require replacement",
        "revoking from a suspected host lets the attacker observe and race the process",
    ]

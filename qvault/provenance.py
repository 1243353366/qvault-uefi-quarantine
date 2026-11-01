"""
qvault.provenance
=================

The envelope every collected artifact must carry, enforced by construction.

The eight mandatory elements
----------------------------
1. **Original-source identification** — what it is and where it came from.
2. **Acquisition timestamp** — integer milliseconds since the Unix epoch, UTC.
3. **SHA-256 digest** — computed here, never accepted from the caller.
4. **Acquisition method** — from a fixed vocabulary, because "how" decides what the
   evidence can support.
5. **Tool and reader version** — both, because a parser bug and a capture bug are
   different failures with different blame.
6. **Coverage and collection errors** — what was attempted, what succeeded, what
   broke and what the break cost.
7. **Chain of custody** — append-only, hash-chained, starting with acquisition.
8. **Cryptographic protection at rest** — authenticated encryption only.

Why the digest is not a parameter
---------------------------------
An envelope whose hash is supplied by the caller records what the caller believed,
not what the file is. `capture()` computes the digest from the bytes it is given, so
a stale or optimistic hash cannot be written. `verify()` recomputes it.

Why coverage is not a footnote
------------------------------
Coverage gaps and collection errors are converted into telemetry gaps by
`telemetry_gaps()`, which feeds the confidence penalty in `qvault/findings.py`
(rule F3). An artifact whose flash read covered 60% is automatically a lower-grade
observation, without anyone having to remember to say so.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Acquisition methods. "how" constrains "what this can prove".
OOB_SPI_READ = "oob_spi_read"
OOB_CHIPOFF = "oob_chipoff_read"
LIVE_RESPONSE = "live_response"
DISK_IMAGE = "disk_image"
MEMORY_CAPTURE = "memory_capture"
PCAP = "pcap"
VENDOR_CAPSULE = "vendor_capsule"
LOG_EXPORT = "log_export"
OTHER = "other"

METHODS = (
    OOB_SPI_READ, OOB_CHIPOFF, LIVE_RESPONSE, DISK_IMAGE, MEMORY_CAPTURE,
    PCAP, VENDOR_CAPSULE, LOG_EXPORT, OTHER,
)

# Which evidence plane each method belongs to (see qvault/limitations.py).
# Recorded so a downstream claim can be checked against the acquisition route.
METHOD_PLANE = {
    OOB_SPI_READ: "firmware_out_of_band",
    OOB_CHIPOFF: "firmware_out_of_band",
    LIVE_RESPONSE: "live_state",
    DISK_IMAGE: "historical_record",
    MEMORY_CAPTURE: "live_state",
    PCAP: "wire",
    VENDOR_CAPSULE: "firmware_via_os",
    LOG_EXPORT: "historical_record",
    OTHER: "unknown",
}

# Authenticated encryption only. Unauthenticated modes are refused outright.
CIPHERS = ("AES-256-GCM", "ChaCha20-Poly1305")

# Names that would indicate key material leaking into an evidence envelope.
FORBIDDEN_KEY_NAMES = frozenset(
    {"key", "dek", "kek", "plaintext_key", "secret", "password", "token"}
)

REQUIRED_FIELDS = (
    "original_source", "acquired_at_ms", "sha256", "acquisition_method",
    "tool", "tool_version", "reader_version", "coverage", "errors",
    "custody", "at_rest",
)


class ProvenanceError(ValueError):
    """Raised when an artifact envelope cannot be constructed honestly."""


@dataclass(frozen=True)
class OriginalSource:
    """What the artifact is, and where it came from before anyone touched it."""

    kind: str          # firmware_flash | file | memory | capture | log | ...
    locator: str       # chip designator, path, offset range, host:iface
    identity: str      # serial, device id, image build, blob hash of the source
    note: str = ""

    def __post_init__(self) -> None:
        for name, value in (("kind", self.kind), ("locator", self.locator),
                            ("identity", self.identity)):
            if not str(value).strip():
                raise ProvenanceError(f"original source requires a non-empty {name}")


@dataclass(frozen=True)
class Coverage:
    """What was attempted, what succeeded, and therefore what is missing."""

    attempted: tuple[str, ...]
    succeeded: tuple[str, ...] = ()
    bytes_read: int | None = None

    def __post_init__(self) -> None:
        if not self.attempted:
            raise ProvenanceError("coverage must declare at least one attempted region")
        extra = set(self.succeeded) - set(self.attempted)
        if extra:
            raise ProvenanceError(f"succeeded regions not attempted: {sorted(extra)}")
        # Default: everything attempted succeeded.
        if not self.succeeded and self.attempted:
            object.__setattr__(self, "succeeded", tuple(self.attempted))

    @property
    def unobserved(self) -> tuple[str, ...]:
        return tuple(r for r in self.attempted if r not in self.succeeded)

    @property
    def fraction(self) -> float:
        return len(self.succeeded) / len(self.attempted)

    @property
    def complete(self) -> bool:
        return not self.unobserved


@dataclass(frozen=True)
class CollectionError:
    """A failure during acquisition, and what it cost."""

    stage: str
    message: str
    effect: str

    def __post_init__(self) -> None:
        for name, value in (("stage", self.stage), ("message", self.message),
                            ("effect", self.effect)):
            if not str(value).strip():
                raise ProvenanceError(
                    f"collection error requires a non-empty {name}: an error without a "
                    "stated effect cannot be assessed for impact"
                )


def _event_digest(payload: dict, prev: str) -> str:
    blob = json.dumps({**payload, "prev": prev}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass(frozen=True)
class CustodyEvent:
    actor: str
    action: str
    at_ms: int
    note: str = ""
    prev: str = ""
    digest: str = ""

    def payload(self) -> dict:
        return {"actor": self.actor, "action": self.action, "at_ms": self.at_ms,
                "note": self.note}

    def computed_digest(self) -> str:
        return _event_digest(self.payload(), self.prev)


@dataclass
class CustodyLog:
    """Append-only, hash-chained. The first event is always the acquisition."""

    events: list[CustodyEvent] = field(default_factory=list)

    def append(self, actor: str, action: str, at_ms: int, note: str = "") -> CustodyEvent:
        if not self.events:
            if action != "acquired":
                raise ProvenanceError(
                    "the first custody event must be 'acquired'; a log that begins "
                    "later cannot show who took the artifact"
                )
        else:
            if at_ms < self.events[-1].at_ms:
                raise ProvenanceError(
                    "custody timestamps must not go backwards; a clock that moves "
                    "backwards breaks the ordering the chain depends on"
                )
        prev = self.events[-1].digest if self.events else ""
        event = CustodyEvent(actor=actor, action=action, at_ms=at_ms, note=note, prev=prev)
        event = CustodyEvent(**{**event.__dict__,
                                "digest": event.computed_digest()})
        self.events.append(event)
        return event

    def verify(self) -> bool:
        """Recompute the chain. Detects edits, insertions and reordering."""
        prev = ""
        last = None
        for event in self.events:
            if event.prev != prev:
                return False
            if event.computed_digest() != event.digest:
                return False
            if last is not None and event.at_ms < last:
                return False
            prev = event.digest
            last = event.at_ms
        return True


@dataclass(frozen=True)
class AtRest:
    """How the artifact is protected at rest. Authenticated encryption only."""

    cipher: str
    key_id: str
    object_id: str
    envelope_version: str = "qvault.atrest.v1"

    def __post_init__(self) -> None:
        if self.cipher not in CIPHERS:
            raise ProvenanceError(
                f"cipher {self.cipher!r} is not in the permitted set {CIPHERS}; "
                "unauthenticated encryption cannot show the artifact was unmodified"
            )
        for name, value in (("key_id", self.key_id), ("object_id", self.object_id)):
            if not str(value).strip():
                raise ProvenanceError(f"at-rest protection requires a non-empty {name}")


@dataclass(frozen=True)
class Artifact:
    """A collected artifact with its complete provenance envelope."""

    original_source: OriginalSource
    acquired_at_ms: int
    sha256: str
    acquisition_method: str
    tool: str
    tool_version: str
    reader_version: str
    coverage: Coverage
    custody: CustodyLog
    at_rest: AtRest
    errors: tuple[CollectionError, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if self.acquisition_method not in METHODS:
            raise ProvenanceError(
                f"acquisition method {self.acquisition_method!r} is not in {METHODS}"
            )
        if not SHA256_RE.match(self.sha256 or ""):
            raise ProvenanceError("sha256 must be 64 lowercase hex characters")
        for name, value in (("tool", self.tool), ("tool_version", self.tool_version),
                            ("reader_version", self.reader_version)):
            if not str(value).strip():
                raise ProvenanceError(
                    f"{name} is mandatory: a bug in the capture tool and a bug in the "
                    "reader are different failures and need different blame"
                )
        if not isinstance(self.acquired_at_ms, int) or self.acquired_at_ms <= 0:
            raise ProvenanceError("acquisition timestamp must be a positive integer (ms, UTC)")
        if not self.custody.events:
            raise ProvenanceError("an artifact without a custody log has no history")
        if self.custody.events[0].action != "acquired":
            raise ProvenanceError("custody must begin with the acquisition event")
        if not self.custody.verify():
            raise ProvenanceError("custody chain does not verify")

    # -- derived --------------------------------------------------------

    @property
    def plane(self) -> str:
        return METHOD_PLANE[self.acquisition_method]

    def telemetry_gaps(self) -> tuple[str, ...]:
        """Convert coverage shortfalls and errors into declared blind spots.

        This is what stops a partial read from being reported as a complete one.
        """
        gaps = [f"unobserved:{r}" for r in self.coverage.unobserved]
        gaps.extend(f"error:{e.stage}" for e in self.errors)
        return tuple(gaps)

    def to_dict(self) -> dict:
        doc = {
            "envelope_version": "qvault.provenance.v1",
            "original_source": {
                "kind": self.original_source.kind,
                "locator": self.original_source.locator,
                "identity": self.original_source.identity,
                "note": self.original_source.note,
            },
            "acquired_at_ms": self.acquired_at_ms,
            "sha256": self.sha256,
            "acquisition_method": self.acquisition_method,
            "plane": self.plane,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "reader_version": self.reader_version,
            "coverage": {
                "attempted": list(self.coverage.attempted),
                "succeeded": list(self.coverage.succeeded),
                "unobserved": list(self.coverage.unobserved),
                "fraction": self.coverage.fraction,
                "bytes_read": self.coverage.bytes_read,
            },
            "errors": [
                {"stage": e.stage, "message": e.message, "effect": e.effect}
                for e in self.errors
            ],
            "custody": [
                {"actor": ev.actor, "action": ev.action, "at_ms": ev.at_ms,
                 "note": ev.note, "prev": ev.prev, "digest": ev.digest}
                for ev in self.custody.events
            ],
            "at_rest": {
                "cipher": self.at_rest.cipher,
                "key_id": self.at_rest.key_id,
                "object_id": self.at_rest.object_id,
                "envelope_version": self.at_rest.envelope_version,
            },
            "note": self.note,
        }
        leaked = FORBIDDEN_KEY_NAMES & {k.lower() for k in doc}
        if leaked:
            raise ProvenanceError(f"envelope would leak key material fields: {sorted(leaked)}")
        return doc

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def capture(
    data: bytes,
    *,
    source: OriginalSource,
    acquired_at_ms: int,
    method: str,
    tool: str,
    tool_version: str,
    reader_version: str,
    coverage: Coverage,
    at_rest: AtRest,
    actor: str,
    errors: tuple[CollectionError, ...] = (),
    note: str = "",
) -> Artifact:
    """Build an envelope, computing the digest from the bytes themselves."""
    if not isinstance(data, (bytes, bytearray)):
        raise ProvenanceError("capture() takes bytes; the digest is of the bytes, not of a path")
    digest = hashlib.sha256(bytes(data)).hexdigest()
    custody = CustodyLog()
    custody.append(actor=actor, action="acquired", at_ms=acquired_at_ms,
                   note=f"{method} via {tool} {tool_version}")
    return Artifact(
        original_source=source,
        acquired_at_ms=acquired_at_ms,
        sha256=digest,
        acquisition_method=method,
        tool=tool,
        tool_version=tool_version,
        reader_version=reader_version,
        coverage=coverage,
        custody=custody,
        at_rest=at_rest,
        errors=errors,
        note=note,
    )


def verify(data: bytes, artifact: Artifact) -> bool:
    """Recompute the digest in constant time."""
    expected = hashlib.sha256(bytes(data)).hexdigest()
    return hmac.compare_digest(expected, artifact.sha256)


def missing_fields(doc: dict) -> list[str]:
    """Which mandatory elements an imported envelope omits.

    Presence is what is checked, not truthiness: an empty `errors` array is a
    complete and honest statement ("no errors occurred"), whereas a missing one is
    an omission.
    """
    return [f for f in REQUIRED_FIELDS if f not in doc or doc[f] is None]

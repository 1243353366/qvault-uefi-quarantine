"""Tests for qvault.provenance — the eight mandatory envelope elements."""

from __future__ import annotations

import json

import pytest

from qvault import findings as F
from qvault import provenance as P
from qvault.provenance import (
    Artifact, AtRest, CollectionError, Coverage, CustodyLog, OriginalSource,
    ProvenanceError, capture,
)

SRC = OriginalSource("firmware_flash", "SPI U3, 0x000000-0xFFFFFF", "board-sn-4417")
REST = AtRest("AES-256-GCM", "kek-case-7", "obj-0001")


def cov(**kw) -> Coverage:
    base = dict(attempted=("bios_region", "me_region"))
    base.update(kw)
    return Coverage(**base)


def art(data: bytes = b"firmware-image", **kw) -> Artifact:
    args = dict(
        source=SRC, acquired_at_ms=1_700_000_000_000, method=P.OOB_SPI_READ,
        tool="flashprog", tool_version="1.4", reader_version="uefi-reader 0.9",
        coverage=cov(), at_rest=REST, actor="analyst:aadi",
    )
    args.update(kw)
    return capture(data, **args)


# --- all eight elements are mandatory ------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("tool", ""),
        ("tool_version", ""),
        ("reader_version", ""),
        ("acquisition_method", "vibes"),
        ("sha256", "deadbeef"),
        ("acquired_at_ms", 0),
    ],
)
def test_artifact_refuses_bad_mandatory_fields(field, value):
    good = art()
    kwargs = {f: getattr(good, f) for f in P.Artifact.__dataclass_fields__}
    kwargs[field] = value
    with pytest.raises(ProvenanceError):
        Artifact(**kwargs)


def test_original_source_requires_kind_locator_and_identity():
    with pytest.raises(ProvenanceError):
        OriginalSource("", "SPI U3", "sn")
    with pytest.raises(ProvenanceError):
        OriginalSource("firmware_flash", "  ", "sn")
    with pytest.raises(ProvenanceError):
        OriginalSource("firmware_flash", "SPI U3", "")


def test_coverage_must_declare_something_attempted():
    with pytest.raises(ProvenanceError):
        Coverage(attempted=())


def test_coverage_cannot_succeed_at_something_not_attempted():
    with pytest.raises(ProvenanceError):
        Coverage(attempted=("bios_region",), succeeded=("me_region",))


def test_missing_fields_reports_omissions_in_imported_envelopes():
    doc = art().to_dict()
    assert P.missing_fields(doc) == []
    del doc["reader_version"]
    del doc["custody"]
    assert set(P.missing_fields(doc)) == {"reader_version", "custody"}


# --- digest is computed, not accepted -----------------------------------


def test_digest_is_computed_from_the_bytes():
    import hashlib

    data = b"some firmware bytes"
    assert art(data).sha256 == hashlib.sha256(data).hexdigest()


def test_capture_rejects_non_bytes():
    with pytest.raises(ProvenanceError):
        capture("C:/firmware.bin", source=SRC, acquired_at_ms=1, method=P.OOB_SPI_READ,
                tool="t", tool_version="1", reader_version="1", coverage=cov(),
                at_rest=REST, actor="a")


def test_verify_detects_tampering():
    data = b"firmware-image"
    a = art(data)
    assert P.verify(data, a) is True
    assert P.verify(data + b"x", a) is False


# --- coverage and errors become telemetry gaps (F3 integration) ----------


def test_complete_coverage_produces_no_gaps():
    assert art().telemetry_gaps() == ()


def test_partial_coverage_produces_gaps():
    a = art(coverage=cov(attempted=("bios_region", "me_region", "ec_region"),
                         succeeded=("bios_region",)))
    assert a.coverage.complete is False
    assert a.coverage.fraction == pytest.approx(1 / 3)
    gaps = a.telemetry_gaps()
    assert "unobserved:me_region" in gaps
    assert "unobserved:ec_region" in gaps


def test_collection_error_must_state_its_effect():
    with pytest.raises(ProvenanceError):
        CollectionError("bios_region", "read timeout", "")
    with pytest.raises(ProvenanceError):
        CollectionError("", "read timeout", "region unread")


def test_an_error_creates_a_gap_even_with_full_region_coverage():
    a = art(errors=(CollectionError("bios_region", "read timeout", "region unread"),))
    assert a.coverage.complete is True
    assert a.telemetry_gaps() == ("error:bios_region",)


def test_coverage_gaps_lower_the_confidence_of_a_finding():
    """The whole point: a 60% read cannot support a CONFIRMED observation."""
    a = art(coverage=cov(attempted=("bios_region", "me_region", "ec_region"),
                         succeeded=("bios_region",)))
    lowered = F.confidence_grade(F.CONFIRMED, a.telemetry_gaps())
    assert lowered == F.INFERRED  # CONFIRMED, two steps down for two unread regions

    single = art(coverage=cov(succeeded=("bios_region",)))
    assert F.confidence_grade(F.CONFIRMED, single.telemetry_gaps()) == F.CORROBORATED


def test_method_maps_to_the_evidence_plane():
    assert art().plane == "firmware_out_of_band"
    assert art(method=P.VENDOR_CAPSULE).plane == "firmware_via_os"
    assert art(method=P.LIVE_RESPONSE).plane == "live_state"
    assert art(method=P.PCAP).plane == "wire"


# --- chain of custody ---------------------------------------------------


def test_custody_starts_with_acquisition():
    log = CustodyLog()
    with pytest.raises(ProvenanceError):
        log.append(actor="a", action="reviewed", at_ms=1000)


def test_custody_timestamps_cannot_go_backwards():
    log = CustodyLog()
    log.append(actor="a", action="acquired", at_ms=2000)
    with pytest.raises(ProvenanceError):
        log.append(actor="a", action="transferred", at_ms=1500)


def test_custody_chain_verifies_and_detects_edits():
    log = CustodyLog()
    log.append(actor="analyst:aadi", action="acquired", at_ms=1000)
    log.append(actor="analyst:reviewer", action="transferred", at_ms=2000, note="case intake")
    log.append(actor="enclave:q", action="sealed", at_ms=3000)
    assert log.verify() is True

    log.events[1] = type(log.events[1])(
        actor="attacker", action="transferred", at_ms=2000, note="",
        prev=log.events[1].prev, digest=log.events[1].digest,
    )
    assert log.verify() is False


def test_custody_ignores_reordering():
    log = CustodyLog()
    log.append(actor="a", action="acquired", at_ms=1000)
    log.append(actor="b", action="transferred", at_ms=2000)
    log.events.reverse()
    assert log.verify() is False


def test_artifact_requires_a_verifying_custody_log():
    good = art()
    broken = CustodyLog()
    broken.append(actor="a", action="acquired", at_ms=1)
    broken.events[0] = type(broken.events[0])(
        actor="a", action="acquired", at_ms=1, note="", prev="", digest="0" * 64
    )
    kwargs = {f: getattr(good, f) for f in P.Artifact.__dataclass_fields__}
    kwargs["custody"] = broken
    with pytest.raises(ProvenanceError):
        Artifact(**kwargs)


# --- protection at rest -------------------------------------------------


def test_unauthenticated_ciphers_are_refused():
    with pytest.raises(ProvenanceError):
        AtRest("AES-256-CBC", "k", "o")
    with pytest.raises(ProvenanceError):
        AtRest("none", "k", "o")


def test_authenticated_ciphers_are_accepted_with_key_and_object_ids():
    for cipher in P.CIPHERS:
        a = AtRest(cipher, "kek-1", "obj-9")
        assert a.cipher == cipher
    with pytest.raises(ProvenanceError):
        AtRest("AES-256-GCM", "", "obj-9")


def test_envelope_refuses_to_leak_key_material_names():
    a = art()
    doc = a.to_dict()
    assert "key" not in doc and "dek" not in doc
    assert doc["at_rest"]["key_id"] == "kek-case-7"


# --- serialisation ------------------------------------------------------


def test_envelope_is_deterministic_and_complete():
    a = art()
    first, second = a.to_json(), art().to_json()
    assert first == second
    doc = json.loads(first)
    for element in ("original_source", "acquired_at_ms", "sha256", "acquisition_method",
                    "tool", "tool_version", "reader_version", "coverage", "errors",
                    "custody", "at_rest"):
        assert element in doc, element


def test_envelope_records_coverage_fraction_and_unobserved():
    a = art(coverage=cov(attempted=("bios_region", "me_region", "ec_region"),
                         succeeded=("bios_region", "me_region")))
    doc = a.to_dict()
    assert doc["coverage"]["fraction"] == pytest.approx(2 / 3)
    assert doc["coverage"]["unobserved"] == ["ec_region"]

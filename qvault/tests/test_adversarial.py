"""Adversarial tests: the tool must degrade or refuse, never falsely certify.

Five attack classes, each asserted at the boundary where a lazy implementation would
quietly succeed: forged evidence, duplicated evidence sources, malformed firmware,
parser exhaustion, and misleading timestamps.

These are tests of *refusal behaviour*. A test that passes because the tool returned
"clean" is a bug in the test.
"""

import os
import time

import pytest

from qvault import budgets as R
from qvault import calibration as K
from qvault import correlate as C
from qvault import findings as F
from qvault import fwdiff as W
from qvault import integrity as N
from qvault import provenance as P
from qvault import separation as S

NOW_MS = 1_760_000_000_000


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def artifact(tmp_path, data=b"firmware bytes", *, acquired_at_ms=NOW_MS):
    src = P.OriginalSource(kind="firmware_flash", locator="SPI U3", identity="ws-01")
    cov = P.Coverage(attempted=("bios",), succeeded=("bios",))
    at_rest = P.AtRest(cipher="AES-256-GCM", key_id="kek-1", object_id="obj-1")
    return P.capture(
        data,
        source=src,
        acquired_at_ms=acquired_at_ms,
        method="oob_spi_read",
        tool="qvault",
        tool_version="0.5.0",
        reader_version="ch341a/1.4",
        coverage=cov,
        at_rest=at_rest,
        actor="analyst:test",
        now_ms=NOW_MS,
    )


def ev(ts, subject="proc", kind=C.CONTACT, plane="historical_record",
       grade=F.INFERRED, fingerprint="", source=""):
    return C.Event(ts=ts, subject=subject, kind=kind, plane=plane, grade=grade,
                   fingerprint=fingerprint, source=source)


def build_fv(files, *, declared_len=None, sig=True, hdr_len=0x38):
    """Minimal firmware volume: header, then 24-byte file headers and bodies.

    An FFS file's size field covers its own header, which is the detail a hand-rolled
    fixture usually gets wrong.
    """
    body = bytearray()
    for guid_byte, payload in files:
        total = 24 + len(payload)
        fh = bytearray(24)
        fh[0:16] = bytes([guid_byte]) * 16
        fh[18] = 0x07
        fh[20:23] = total.to_bytes(3, "little")
        body += fh + payload
        body += b"\x00" * ((-len(body)) % 8)

    total = hdr_len + len(body)
    if declared_len is not None:
        total = declared_len
    head = bytearray(hdr_len)
    head[0x28:0x2C] = b"_FVH" if sig else b"_XXX"
    head[0x20:0x28] = total.to_bytes(8, "little")
    head[0x30:0x32] = hdr_len.to_bytes(2, "little")
    return bytes(head) + bytes(body)


# --------------------------------------------------------------------------
# 1. forged evidence
# --------------------------------------------------------------------------


def test_a_flipped_byte_breaks_the_recorded_digest(tmp_path):
    art = artifact(tmp_path, b"original bytes")
    assert P.verify(b"original bytes", art) is True
    assert P.verify(b"original bytez", art) is False


def test_an_envelope_missing_a_mandatory_element_is_reported(tmp_path):
    doc = artifact(tmp_path).to_dict()
    del doc["coverage"]
    assert "coverage" in P.missing_fields(doc)


def test_an_empty_error_list_is_complete_but_a_missing_one_is_not(tmp_path):
    doc = artifact(tmp_path).to_dict()
    assert doc["errors"] == []
    assert P.missing_fields(doc) == []
    del doc["errors"]
    assert "errors" in P.missing_fields(doc)


def test_a_finding_that_claims_cleanliness_is_flagged():
    doc = {
        "identifier": "F-1",
        "verdict": "clean",
        "observation": {"grade": "CONFIRMED", "telemetry_gaps": [],
                        "confidence_after_gaps": "CONFIRMED"},
        "benign_explanations": [{"description": "x", "disposition": "ruled_out",
                                 "reasoning": "checked"}],
    }
    kinds = {v["rule"] for v in F.audit_finding(doc)}
    assert any("clean" in k for k in kinds), kinds


def test_a_finding_without_a_benign_alternative_is_flagged():
    doc = {
        "identifier": "F-2",
        "observation": {"grade": "CORROBORATED", "telemetry_gaps": [],
                        "confidence_after_gaps": "CORROBORATED"},
        "benign_explanations": [],
    }
    assert F.audit_finding(doc)


def test_an_attestation_relaying_the_subjects_own_report_is_refused():
    att = S.Attestation(
        subject="db_parser",
        attestor="engine_verifier",
        evidence_class=S.SELF_REPORT,
        method="tool hash reported by the tool",
    )
    with pytest.raises(S.SeparationError):
        S.verify(att)


def test_evidence_stored_beside_the_code_it_describes_is_refused(tmp_path):
    (tmp_path / "code.py").write_text("x = 1\n")
    m = N.build_manifest(str(tmp_path))
    with pytest.raises(N.IntegrityError):
        N.verify_tree(str(tmp_path), m["digest"], provenance=N.SELF_EMBEDDED)


# --------------------------------------------------------------------------
# 2. duplicated evidence sources
# --------------------------------------------------------------------------


def test_one_record_copied_twice_cannot_supply_two_planes():
    """Relabelling a duplicate must not manufacture independence."""
    dupes = [ev(1000, plane=p, fingerprint="digest-abc")
             for p in ("historical_record", "wire", "live_state")]
    out = C.assess_cluster(dupes)
    assert out["duplicate_evidence"] is True
    assert out["grade"] == F.INFERRED


def test_deduplicate_counts_the_copies_it_dropped():
    events = [ev(1000, fingerprint="d1"), ev(1000, fingerprint="d1"), ev(1100, fingerprint="d2")]
    unique, dropped = C.deduplicate(events)
    assert len(unique) == 2 and dropped == 1


def test_identical_events_without_a_fingerprint_also_collapse():
    events = [ev(1000, source="authd.log") for _ in range(5)]
    unique, dropped = C.deduplicate(events)
    assert len(unique) == 1 and dropped == 4


def test_independent_evidence_still_raises_a_grade():
    events = [
        ev(1000, kind=C.INSTALL, plane="historical_record", fingerprint="a", grade=F.CORROBORATED),
        ev(1010, kind=C.EXECUTION, plane="live_state", fingerprint="b", grade=F.CORROBORATED),
        ev(1020, kind=C.CONTACT, plane="wire", fingerprint="c", grade=F.CORROBORATED),
    ]
    out = C.assess_cluster(events)
    assert out["duplicate_evidence"] is False
    assert out["raised"] is True


def test_three_feeds_quoting_one_upstream_are_not_corroboration():
    from qvault import limitations as L
    circular = [L.IntelFeed(name=n, upstream="same-vendor", age_days=1) for n in ("a", "b", "c")]
    assert L.intel_trust(circular)["standing"] == "circular"

    two_upstreams = [
        L.IntelFeed(name="a", upstream="vendor-1", age_days=1),
        L.IntelFeed(name="b", upstream="vendor-2", age_days=1),
    ]
    out = L.intel_trust(two_upstreams)
    assert out["standing"] == "uncorroborated", out["standing"]
    assert out["supports_malicious_claim"] is False


# --------------------------------------------------------------------------
# 3. malformed firmware images
# --------------------------------------------------------------------------


def test_an_image_with_no_volume_header_is_unreadable_not_clean():
    img = W.parse_firmware(b"not firmware at all" * 100)
    assert W.parse_status(img) == "unreadable"
    assert W.parse_gaps(img)


def test_a_truncated_volume_is_reported_with_both_lengths():
    data = build_fv([(0x11, b"AAA")], declared_len=0x1000)[:200]
    img = W.parse_firmware(data)
    assert W.parse_status(img) in ("unreadable", "partial")
    assert any("truncated" in g or "claims" in g for g in W.parse_gaps(img))


def test_an_absurd_declared_volume_length_does_not_allocate():
    data = bytearray(build_fv([(0x11, b"AAA")]))
    data[0x20:0x28] = (2 ** 62).to_bytes(8, "little")
    img = W.parse_firmware(bytes(data))
    assert W.parse_status(img) == "unreadable"


def test_a_file_claiming_more_than_the_volume_holds_is_reported():
    data = bytearray(build_fv([(0x11, b"AAA")]))
    start = 0x38  # first file header sits at the aligned end of the FV header
    data[start + 20:start + 23] = (0xFFFF).to_bytes(3, "little")
    img = W.parse_firmware(bytes(data))
    assert W.parse_status(img) in ("partial", "unreadable")


def test_a_well_formed_image_parses_with_no_diagnostics():
    img = W.parse_firmware(build_fv([(0x11, b"AAAA"), (0x22, b"BBBB")]))
    assert W.parse_status(img) == "parsed"
    assert W.parse_gaps(img) == ()


def test_parse_status_never_returns_a_cleanliness_word():
    for payload in (b"", b"\x00" * 64, build_fv([(0x11, b"AAA")])):
        status = W.parse_status(W.parse_firmware(payload))
        assert status in ("parsed", "partial", "unreadable")


# --------------------------------------------------------------------------
# 4. parser exhaustion
# --------------------------------------------------------------------------


def test_an_expansion_bomb_breaks_the_budget():
    usage = R.Usage(wall_s=900, memory_mb=4096, output_bytes=2_000_000_000,
                    open_files=10, artifact_bytes=399)
    out = R.check("db_parser", usage)
    assert out["within_budget"] is False
    assert out["expansion_alert"] is True


def test_a_budget_kill_becomes_a_telemetry_gap_not_a_clean_parse():
    usage = R.Usage(wall_s=900, memory_mb=64, output_bytes=10, open_files=1,
                    artifact_bytes=1000)
    gaps = R.gaps_for("db_parser", usage)
    assert gaps and any("budget_exceeded" in g for g in gaps)


def test_a_killed_parse_cannot_be_graded_confirmed():
    usage = R.Usage(wall_s=900, memory_mb=64, output_bytes=10, open_files=1,
                    artifact_bytes=1000)
    obs = R.observation("db_parser", usage, "parsed what it could")
    lowered = F.confidence_grade(F.CONFIRMED, obs.telemetry_gaps)
    assert lowered != F.CONFIRMED, lowered
    assert F._RANK[lowered] < F._RANK[F.CONFIRMED]


def test_more_matches_than_the_listing_cap_are_still_counted():
    from vendor.zbtriage import result as zbt
    from qvault import zbt_bridge as B
    mr = zbt.ModuleResult(name="backup")
    hit = dict(indicator="evil.example", location="Manifest.db", detail="", tier="A",
               source="r", evidence=zbt.EV_ON_DISK)
    for _ in range(500):
        mr.add_hit(zbt.Hit(**hit))
    assert B.serious_match_count(mr) == 500
    assert any(g.startswith("hits_truncated") for g in B.module_gaps(mr))


# --------------------------------------------------------------------------
# 5. misleading timestamps
# --------------------------------------------------------------------------


def test_an_artifact_acquired_in_the_future_is_refused(tmp_path):
    with pytest.raises(P.ProvenanceError):
        artifact(tmp_path, acquired_at_ms=NOW_MS + 86_400_000 * 400)


def test_a_zero_timestamp_is_refused(tmp_path):
    with pytest.raises(P.ProvenanceError):
        artifact(tmp_path, acquired_at_ms=0)


def test_a_small_clock_skew_is_tolerated(tmp_path):
    art = artifact(tmp_path, acquired_at_ms=NOW_MS + P.MAX_CLOCK_SKEW_MS // 2)
    assert art.sha256


def test_out_of_order_events_do_not_reorder_the_cluster():
    events = [ev(2000, kind=C.INSTALL, fingerprint="z"), ev(1000, kind=C.CONTACT, fingerprint="a")]
    out = C.assess_cluster(events)
    assert out["span_s"] == 1000


def test_a_negative_span_is_impossible_after_sorting():
    events = [ev(1500, kind=C.CONTACT, fingerprint="a"), ev(500, kind=C.INSTALL, fingerprint="b")]
    assert C.assess_cluster(events)["span_s"] == 1000


def test_events_far_apart_do_not_form_one_cluster():
    events = [ev(1000, subject="a", fingerprint="a"), ev(999_999, subject="z", fingerprint="z")]
    clusters = C.build_clusters(events, window_s=300)
    assert len(clusters) == 2


def test_the_calibration_harness_refuses_to_call_a_small_corpus_measurable():
    bench = K.Bench("tiny").add("c1", "malicious", F.SUSPICIOUS)
    out = K.evaluate(bench)
    assert out["measurable"] is False
    assert out["zero_claim_allowed"] is False

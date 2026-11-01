"""Tests for the upstream bridge and the correlation engine."""

from __future__ import annotations

import pytest
from vendor.zbtriage import result as zbt

from qvault import correlate as C
from qvault import findings as F
from qvault import limitations as L
from qvault import zbt_bridge as B
from qvault.zbt_bridge import BridgeError


def hit(evidence=zbt.EV_ON_DISK, indicator="evil.example", **kw) -> zbt.Hit:
    base = dict(indicator=indicator, location="/Users/a/Library/x.db",
                detail="matched IOC", tier="A", confidence="high",
                source="vendor-report-2023", family="Predator")
    base.update(kw)
    return zbt.Hit(evidence=evidence, **base)


def mod(hits=(), checks=None, name="ios_backup", **kw) -> zbt.ModuleResult:
    if checks is None:
        checks = [zbt.Check(name="backup-dbs", ran=True)]
    return zbt.ModuleResult(name=name, hits=list(hits), checks=list(checks), **kw)


# --- the anti-drift guard ------------------------------------------------


def test_evidence_vocabulary_is_fully_mapped():
    B.assert_vocabulary()
    assert set(B.EVIDENCE_MAP) == set(zbt.EVIDENCE_ORDER)


def test_a_new_upstream_grade_would_fail_the_guard(monkeypatch):
    monkeypatch.setattr(zbt, "EVIDENCE_ORDER", list(zbt.EVIDENCE_ORDER) + ["brand-new"])
    with pytest.raises(BridgeError) as e:
        B.assert_vocabulary()
    assert "brand-new" in str(e.value)


def test_every_mapped_plane_exists_in_the_limitations_model():
    for evidence, m in B.EVIDENCE_MAP.items():
        assert m["plane"] in L.PROFILES, evidence
        assert m["grade"] in F.GRADES, evidence


# --- grading -------------------------------------------------------------


def test_on_disk_fingerprint_is_corroborated_on_the_historical_plane():
    m = B.mapping_for(zbt.EV_ON_DISK)
    assert m["grade"] == F.CORROBORATED
    assert m["plane"] == L.HISTORICAL
    assert m["known"] is True


def test_referenced_stays_benign_and_low_grade():
    assert B.is_serious(zbt.EV_REFERENCED) is False
    assert B.mapping_for(zbt.EV_REFERENCED)["grade"] == F.HYPOTHESIS


def test_unknown_evidence_is_serious_but_not_inflated():
    m = B.mapping_for("some-new-artifact-class")
    assert B.is_serious("some-new-artifact-class") is True   # upstream's deny-list
    assert m["grade"] == F.HYPOTHESIS                        # not corroborated
    assert m["known"] is False


def test_is_serious_delegates_to_upstream():
    assert B.is_serious(zbt.EV_ON_DISK) is True
    assert B.is_serious(zbt.EV_REFERENCED) is False
    assert B.is_serious("") is True


# --- coverage becomes telemetry gaps ------------------------------------


def test_unrun_checks_become_gaps():
    m = mod(checks=[zbt.Check("dns-cache", ran=False, reason="service disabled"),
                    zbt.Check("safari", ran=True)])
    gaps = B.module_gaps(m)
    assert "check_not_run:dns-cache" in gaps
    assert "check_not_run:safari" not in gaps


def test_module_with_no_checks_is_unknown_and_gapped():
    m = mod(checks=[])
    assert m.status == zbt.UNKNOWN
    assert any(g.startswith("module_status:") for g in B.module_gaps(m))


def test_skipped_records_are_a_gap():
    m = mod(skipped=42)
    assert any(g.startswith("records_skipped:") for g in B.module_gaps(m))


def test_observations_carry_gaps_and_are_not_findings():
    m = mod(hits=[hit()], checks=[zbt.Check("b", ran=False)])
    obs = B.observations(m)
    assert len(obs) == 1
    assert isinstance(obs[0], F.Observation)
    assert not isinstance(obs[0], F.Finding)
    assert "check_not_run:b" in obs[0].telemetry_gaps
    # A gap lowers the grade; CORROBORATED minus one step.
    assert obs[0].confidence == F.INFERRED


# --- the device verdict --------------------------------------------------


def test_hits_yield_suspicious_never_malicious():
    v = B.run_verdict([mod(hits=[hit()])])
    assert v["verdict"] == F.SUSPICIOUS_VERDICT
    assert v["serious_hits"] == 1
    assert "limited" in v["adversarial_value"]


def test_no_hits_with_gaps_is_inconclusive():
    v = B.run_verdict([mod(checks=[zbt.Check("b", ran=False)])])
    assert v["verdict"] == F.INCONCLUSIVE
    assert v["gaps"]


def test_fully_run_modules_never_produce_a_clean_word():
    v = B.run_verdict([mod(checks=[zbt.Check("b", ran=True)])])
    assert v["verdict"] == F.NO_EVIDENCE_FOUND
    assert v["verdict"] not in F.FORBIDDEN_VERDICTS
    assert B.D1_LINE in v["statement"]


def test_only_referenced_hits_do_not_raise_the_verdict():
    v = B.run_verdict([mod(hits=[hit(evidence=zbt.EV_REFERENCED)])])
    assert v["serious_hits"] == 0
    assert v["verdict"] == F.NO_EVIDENCE_FOUND


# --- promotion and attribution ------------------------------------------


def test_promotion_requires_a_benign_explanation():
    obs = B.observations(mod(hits=[hit()]))[0]
    with pytest.raises(F.FindingError):
        B.promote(obs, benign_explanations=())


def test_promotion_cannot_exceed_observation_without_attribution():
    """A graded observation plus a benign alternative is still not an accusation."""
    obs = B.observations(mod(hits=[hit()]))[0]
    benign = (F.BenignExplanation("shared CDN", F.NOT_EXCLUDED, "not checked"),)
    finding = B.promote(obs, benign)
    assert finding.status == F.OBSERVATION
    assert finding.benign_unexcluded is True

    attributed = B.promote(
        obs, benign,
        F.Attribution("Predator", F.CORROBORATED, "two independent vendor reports"),
    )
    assert attributed.status == F.SUSPICIOUS   # capped by the open benign explanation


def test_attribution_refused_on_a_single_feed():
    refusal = B.attribution_refusal(hit(), [L.IntelFeed("zbt-iocs", "vendor-report-2023", 30)])
    assert refusal["refused"] is True
    assert refusal["standing"] == "single_source"
    assert "two independently validated upstreams" in refusal["why"]


def test_attribution_allowed_with_two_independent_upstreams():
    feeds = [L.IntelFeed("a", "vendor-x", 10, validated_independently=True),
             L.IntelFeed("b", "cert-y", 10, validated_independently=True)]
    assert B.attribution_refusal(hit(), feeds) is None


def test_ioc_evidence_has_no_adversarial_value():
    v = B.adversarial_value(zbt.EV_ON_DISK)
    assert v["adversarial_confidence"] == "none"
    assert v["plane"] == L.HISTORICAL


# --- correlation ---------------------------------------------------------


def ev(ts, subject="com.x", kind=C.EXECUTION, plane="historical_record",
       grade=F.INFERRED, benign="") -> C.Event:
    return C.Event(ts=ts, subject=subject, kind=kind, plane=plane, grade=grade, benign=benign)


def test_same_subject_clusters_across_time():
    clusters = C.build_clusters([ev(0), ev(86_400, kind=C.CONTACT)])
    assert len(clusters) == 1


def test_complementary_kinds_join_across_subjects_within_the_window():
    clusters = C.build_clusters([
        ev(1000, subject="app.a", kind=C.INSTALL),
        ev(1100, subject="proc.b", kind=C.EXECUTION),
    ])
    assert len(clusters) == 1


def test_same_kind_across_subjects_does_not_join():
    clusters = C.build_clusters([
        ev(1000, subject="app.a", kind=C.CONTACT),
        ev(1010, subject="app.b", kind=C.CONTACT),
    ])
    assert len(clusters) == 2


def test_distant_complementary_events_do_not_join():
    clusters = C.build_clusters([
        ev(0, subject="a", kind=C.INSTALL), ev(90_000, subject="b", kind=C.EXECUTION)])
    assert len(clusters) == 2


def test_temporal_proximity_alone_never_raises_a_grade():
    """Same plane, same kind, same minute: four events, one source of truth."""
    cluster = [ev(1000 + i, subject=f"p{i}", kind=C.CONTACT) for i in range(4)]
    # same kind + different subjects do not even join; force them into one cluster.
    a = C.assess_cluster(cluster)
    assert a["capped_by_single_plane"] is True
    assert a["grade"] == F.INFERRED
    assert a["raised"] is False


def test_three_kinds_across_two_planes_raises_the_grade():
    cluster = [
        ev(1000, kind=C.INSTALL, plane="historical_record", grade=F.CORROBORATED),
        ev(1050, kind=C.EXECUTION, plane="live_state", grade=F.CORROBORATED),
        ev(1090, kind=C.CONTACT, plane="wire", grade=F.CORROBORATED),
    ]
    a = C.assess_cluster(cluster)
    assert a["raised"] is True
    assert a["grade"] == F.CONFIRMED
    assert a["status"] == "correlated"


def test_one_plane_caps_even_a_rich_cluster():
    cluster = [
        ev(1000, kind=C.INSTALL, grade=F.CORROBORATED),
        ev(1010, kind=C.EXECUTION, grade=F.CORROBORATED),
        ev(1020, kind=C.PERSISTENCE, grade=F.CORROBORATED),
    ]
    a = C.assess_cluster(cluster)
    assert a["capped_by_single_plane"] is True
    assert a["grade"] == F.INFERRED


def test_benign_candidates_are_reported_and_their_absence_is_flagged():
    with_benign = C.assess_cluster([ev(1000, benign="app updater")])
    assert with_benign["benign_candidates"] == ["app updater"]
    assert with_benign["unresolved_gaps"] == []

    without = C.assess_cluster([ev(1000)])
    assert without["unresolved_gaps"]
    assert "not evidence that none exists" in without["unresolved_gaps"][0]


def test_clustering_is_order_independent():
    events = [ev(1000, subject="a", kind=C.INSTALL), ev(1050, subject="b", kind=C.EXECUTION),
              ev(9000, subject="z", kind=C.CONTACT)]
    forward = [sorted(c, key=lambda e: (e.ts, e.subject)) for c in C.build_clusters(events)]
    backward = [sorted(c, key=lambda e: (e.ts, e.subject))
                for c in C.build_clusters(list(reversed(events)))]
    assert forward == backward


def test_unknown_kind_is_rejected():
    with pytest.raises(C.CorrelationError):
        ev(0, kind="exfiltrate")


def test_assess_summarises_without_overclaiming():
    out = C.assess([ev(1000, kind=C.INSTALL), ev(1050, subject="b", kind=C.EXECUTION,
                                                  plane="live_state")])
    assert out["event_count"] == 2
    assert "worth a look" in out["statement"]


# --- the vendored detector must match its recorded digest -----------------


def test_vendored_detector_matches_its_recorded_tree_digest():
    """Silent edits to the vendored engine are a supply-chain change, not a refactor."""
    import hashlib
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent.parent
    manifest = root / "vendor" / "UPSTREAM.sha256"
    assert manifest.exists(), "vendor/UPSTREAM.sha256 is missing"
    recorded = hashlib.sha256(manifest.read_bytes()).hexdigest()

    lines = []
    for f in sorted((root / "vendor" / "zbtriage").rglob("*")):
        if f.is_file() and "__pycache__" not in str(f):
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  "
                         f"{f.relative_to(root / 'vendor').as_posix()}")
    rebuilt = hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()
    assert rebuilt == recorded, (
        "vendored zbtriage differs from vendor/UPSTREAM.sha256: re-vendor deliberately "
        "and update the manifest, do not edit the detector in place"
    )


def test_upstream_release_is_named_not_just_a_commit():
    from pathlib import Path

    text = (Path(__file__).resolve().parent.parent.parent / "vendor" / "UPSTREAM.md").read_text()
    assert "v2.0.2" in text
    assert "90148eae72b722b59fb4f191daf959b21a002bb0" in text
    assert "@interplains" in text


def test_truncated_matches_are_counted_not_capped():
    """The incident upstream documented: 291k matches must not report as 100."""
    mr = zbt.ModuleResult(name="backup")
    for _ in range(zbt.HIT_LIST_LIMIT + 950):
        mr.add_hit(hit(indicator="evil.example"))
    assert len(mr.hits) == zbt.HIT_LIST_LIMIT
    assert B.total_matches(mr) == zbt.HIT_LIST_LIMIT + 950
    assert B.serious_match_count(mr) == zbt.HIT_LIST_LIMIT + 950
    assert B.truncated_summary(mr) == [("evil.example", zbt.HIT_LIST_LIMIT + 950)]


def test_truncation_is_a_telemetry_gap_and_degrades_confidence():
    mr = zbt.ModuleResult(name="backup")
    for _ in range(zbt.HIT_LIST_LIMIT + 5):
        mr.add_hit(hit(indicator="evil.example"))
    gaps = B.module_gaps(mr)
    assert any(g.startswith("hits_truncated") for g in gaps)
    obs = B.observations(mr)[0]
    assert obs.confidence == F.INFERRED   # CORROBORATED, one step lower
    assert F._RANK[obs.confidence] < F._RANK[obs.grade]


def test_verdict_reports_true_count_and_how_many_are_enumerated():
    mr = zbt.ModuleResult(name="backup")
    for _ in range(zbt.HIT_LIST_LIMIT + 900):
        mr.add_hit(hit(indicator="evil.example"))
    v = B.run_verdict([mr])
    assert v["serious_hits"] == zbt.HIT_LIST_LIMIT + 900
    assert v["listed_hits"] == zbt.HIT_LIST_LIMIT
    assert v["truncated"] == [{"indicator": "evil.example",
                              "count": zbt.HIT_LIST_LIMIT + 900}]
    assert "enumerated in full" in v["statement"]


def test_benign_overflow_does_not_raise_the_verdict():
    mr = zbt.ModuleResult(name="browser")
    for _ in range(zbt.HIT_LIST_LIMIT + 500):
        mr.add_hit(hit(evidence=zbt.EV_REFERENCED, indicator="news.example"))
    assert B.serious_match_count(mr) == 0
    assert B.run_verdict([mr])["verdict"] == F.NO_EVIDENCE_FOUND

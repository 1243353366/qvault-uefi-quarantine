"""Tests for credential revocation, resource budgets, and the pillar ledger."""

from __future__ import annotations

import pytest

from qvault import budgets as R
from qvault import findings as F
from qvault import isolation as I
from qvault import pillars as P
from qvault import revoke as V


# --- revocation ordering -------------------------------------------------


def cred(identifier="tok", kind=V.REFRESH_TOKEN, **kw) -> V.Credential:
    return V.Credential(identifier=identifier, kind=kind, **kw)


def test_refresh_tokens_are_revoked_before_access_tokens():
    """Revoking an access token while the refresh grant survives does nothing."""
    plan = V.plan_revocation([
        cred("access", V.SESSION_TOKEN),
        cred("refresh", V.REFRESH_TOKEN),
    ])
    order = [s.identifier for s in plan["steps"]]
    assert order == ["refresh", "access"]
    assert "mints other credentials" in plan["steps"][0].why


def test_shared_secrets_go_last():
    plan = V.plan_revocation([
        cred("shared", V.SHARED_SECRET),
        cred("key", V.API_KEY),
        cred("grant", V.OAUTH_GRANT),
    ])
    assert [s.identifier for s in plan["steps"]] == ["grant", "key", "shared"]


def test_every_step_carries_a_verification_and_a_compensation():
    plan = V.plan_revocation([cred(), cred("k", V.SSH_KEY)])
    for step in plan["steps"]:
        assert step.verification and step.action and step.compensation


def test_empty_inventory_is_refused():
    with pytest.raises(V.RevocationError):
        V.plan_revocation([])


def test_unknown_kind_is_rejected():
    with pytest.raises(V.RevocationError):
        cred(kind="magic_cookie")


# --- unrevocable material ------------------------------------------------


def test_credential_without_a_channel_is_not_called_revoked():
    plan = V.plan_revocation([cred("devcert", V.DEVICE_CERT, has_revocation_channel=False)])
    assert plan["steps"] == []
    assert len(plan["unrevocable"]) == 1
    assert "replace or rotate" in plan["unrevocable"][0].action
    assert "cannot be revoked and need replacement" in plan["statement"]


# --- driving revocation from a compromised host -------------------------


def test_revoking_from_the_compromised_host_is_flagged_unsafe():
    plan = V.plan_revocation([cred()], compromised_host="ws-01", revoking_from_host="ws-01")
    assert plan["safe_to_proceed"] is False
    assert "observe each step" in plan["warnings"][0]


def test_revoking_from_a_clean_host_is_safe():
    plan = V.plan_revocation([cred()], compromised_host="ws-01", revoking_from_host="ws-02")
    assert plan["safe_to_proceed"] is True


# --- verification, not intention ----------------------------------------


def test_a_requested_revocation_is_not_a_revocation():
    plan = V.plan_revocation([cred()])
    records = [V.Record(step=plan["steps"][0], status="requested")]
    out = V.verify(records)
    assert out["verdict"] == "requested_only"
    assert "A request is not a revocation" in out["statement"]
    assert out["pending"] == ["tok"]


def test_confirmed_revocations_verify():
    plan = V.plan_revocation([cred("a", V.SESSION_TOKEN), cred("b", V.REFRESH_TOKEN)])
    records = [V.Record(step=s, status="confirmed") for s in plan["steps"]]
    out = V.verify(records)
    assert out["verdict"] == "revoked"
    assert out["confirmed"] == 2
    assert out["still_usable"] == []


def test_a_failed_revocation_keeps_the_verdict_incomplete():
    plan = V.plan_revocation([cred("k", V.API_KEY)])
    out = V.verify([V.Record(step=plan["steps"][0], status="failed")])
    assert out["verdict"] == "incomplete"
    assert out["still_usable"] == ["k"]   # offline-capable and not confirmed


def test_offline_capable_survivors_are_named_as_gaps():
    plan = V.plan_revocation([cred("k", V.SSH_KEY)])
    assert any("usable without touching the issuer" in g for g in plan["gaps"])


def test_incomplete_inventory_is_an_explicit_gap():
    plan = V.plan_revocation([cred()], inventory_complete=False)
    assert any("nothing can revoke a credential nobody enumerated" in g for g in plan["gaps"])


def test_limits_state_that_revocation_is_not_eradication():
    text = " ".join(V.limits())
    assert "does not remove the implant" in text
    assert "remain valid until expiry" in text


# --- resource budgets ----------------------------------------------------


def test_every_isolated_component_has_a_complete_budget():
    assert R.audit_budgets() == []


def test_usage_within_budget_passes():
    usage = R.Usage(wall_s=10, memory_mb=100, output_bytes=1000, open_files=5,
                    artifact_bytes=4096)
    assert R.assert_within(I.DB_PARSER, usage)["within_budget"] is True


def test_exceeding_wall_time_is_refused_with_a_kill_action():
    usage = R.Usage(wall_s=R.BUDGETS[I.DB_PARSER]["wall_s"] + 1)
    with pytest.raises(R.BudgetExceeded) as e:
        R.assert_within(I.DB_PARSER, usage)
    assert "kill the component" in str(e.value)


def test_output_expansion_attack_is_flagged():
    """The motivating incident: a tiny artifact producing gigabytes."""
    usage = R.Usage(artifact_bytes=399, output_bytes=2 * 1024 * 1024 * 1024,
                    wall_s=5, memory_mb=10, open_files=2)
    result = R.check(I.DB_PARSER, usage)
    assert result["expansion_alert"] is True
    assert any("expansion_ratio" in g for g in R.gaps_for(I.DB_PARSER, usage))


def test_components_forbidden_from_reading_artifacts_are_enforced():
    usage = R.Usage(artifact_bytes=1)
    result = R.check(I.REPORT_GENERATION, usage)
    assert "artifact_bytes_forbidden" in result["exceeded"]


def test_a_budget_kill_degrades_the_observation():
    usage = R.Usage(wall_s=999, artifact_bytes=1024, output_bytes=1024)
    obs = R.observation(I.DB_PARSER, usage, "parsed 12 rows before timeout")
    assert obs.grade == F.HYPOTHESIS
    assert any(g.startswith("budget_exceeded:") for g in obs.telemetry_gaps)
    # F3: the gaps lower it again.
    assert obs.confidence == F.UNKNOWN


def test_unknown_component_budget_is_rejected():
    with pytest.raises(KeyError):
        R.check("my_script", R.Usage())


# --- the pillar ledger ---------------------------------------------------


def test_all_seven_pillars_are_present():
    assert [p["id"] for p in P.PILLARS] == ["P1", "P2", "P3", "P4", "P5", "P6", "P7"]


def test_every_requirement_resolves_to_real_code_and_a_real_test():
    P.assert_traceable()


def test_no_pillar_is_implemented_while_holding_a_required_gap():
    P.assert_consistent()
    for row in P.audit()["pillars"]:
        if row["status"] == P.IMPLEMENTED:
            assert row["gaps"] == []


def test_containment_pillar_covers_both_new_capabilities():
    p6 = next(p for p in P.PILLARS if p["id"] == "P6")
    modules = {r["module"] for r in p6["requirements"]}
    assert {"budgets", "revoke", "isolation", "containment"} <= modules


def test_audit_reports_counts_and_a_statement():
    out = P.audit()
    assert set(out["counts"]) == {P.IMPLEMENTED, P.PARTIAL, P.GAP}
    assert sum(out["counts"].values()) == 7
    assert "Partial means" in out["statement"]


def test_gap_register_lists_everything_unfinished():
    gaps = P.gap_register()
    assert gaps
    for g in gaps:
        assert g["status"] in (P.PARTIAL, P.GAP)
        assert g["why_not"]


def test_a_falsely_claimed_pillar_is_caught():
    """The point of the ledger: it cannot claim what it has not built."""
    broken = {"id": "PX", "name": "fake", "declared": P.IMPLEMENTED, "requirements": [
        {"req": "r", "module": "findings", "symbol": "Finding",
         "test": "qvault/tests/test_findings.py", "status": P.GAP, "limit": "absent"}]}
    P.PILLARS.append(broken)
    try:
        with pytest.raises(P.PillarError):
            P.assert_consistent()
    finally:
        P.PILLARS.pop()

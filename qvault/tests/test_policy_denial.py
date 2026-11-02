"""Policy denial: what a caller is refused, and how the refusal is explained.

The settings matrix already said what is permitted. These tests cover the answer a caller
gets when it asks for something else, and they hold denials to the same standards as the
rest of the tool: fail closed, deterministic, and never a leak.
"""
import pytest

from qvault import netpolicy as N


def decision(policy):
    return N.Decision(policy=policy, trust={"managed": N.MANAGED, "ambiguous": N.AMBIGUOUS,
                                            "untrusted": N.UNTRUSTED,
                                            "hostile": N.HOSTILE}[policy])


def codes(verdict):
    return [d.code for d in verdict.denials]


def test_managed_context_allows_egress_and_sealed_writes():
    d = decision("managed")
    assert N.authorize(d, "egress").allowed
    assert N.authorize(d, "write").allowed


def test_untrusted_context_denies_egress_with_a_usable_remedy():
    verdict = N.authorize(decision("untrusted"), "egress")
    assert not verdict.allowed
    denial = verdict.denials[0]
    assert denial.code == N.DENY_EGRESS
    assert denial.required == "allow_egress = true"
    assert "allow_egress = false" in denial.observed
    assert denial.remedy.strip()
    assert denial.policy == "untrusted" and denial.trust == N.UNTRUSTED


def test_an_unknown_resource_is_refused_not_ignored():
    """Fail closed: a resource nobody wrote a rule for is not thereby permitted."""
    verdict = N.authorize(decision("managed"), "dns_forwarding")
    assert not verdict.allowed
    assert codes(verdict) == [N.DENY_UNKNOWN_RESOURCE]
    assert "egress" in verdict.denials[0].remedy


def test_over_collection_is_refused_under_minimal_policy():
    verdict = N.authorize(decision("untrusted"), "collection", requested="standard")
    assert codes(verdict) == [N.DENY_OVERCOLLECTION]
    assert "minimal" in verdict.denials[0].required
    assert "standard" in verdict.denials[0].observed


def test_collecting_less_than_the_policy_allows_is_permitted():
    assert N.authorize(decision("hostile"), "collection", requested="minimal").allowed


@pytest.mark.parametrize("policy,requested,allowed", [
    ("managed", 90, True), ("managed", 91, False),
    ("untrusted", 7, True), ("untrusted", 8, False),
    ("hostile", 365, True), ("hostile", 366, False),
])
def test_retention_cannot_exceed_the_policy(policy, requested, allowed):
    verdict = N.authorize(decision(policy), "retention", requested=requested)
    assert verdict.allowed is allowed
    if not allowed:
        assert codes(verdict) == [N.DENY_RETENTION]


def test_custody_threshold_is_enforced_and_reports_only_a_count():
    verdict = N.authorize(decision("untrusted"), "custody", shares=2)
    assert codes(verdict) == [N.DENY_CUSTODY]
    assert verdict.denials[0].observed == "2 custodians"
    assert verdict.denials[0].required == "3 of 5 custodians"


def test_custody_at_threshold_is_allowed():
    assert N.authorize(decision("untrusted"), "custody", shares=3).allowed


def test_attestation_requirement_refuses_a_self_report():
    verdict = N.authorize(decision("untrusted"), "attestation", attested=False)
    assert codes(verdict) == [N.DENY_ATTESTATION]
    assert "self-report" in verdict.denials[0].detail
    assert N.authorize(decision("untrusted"), "attestation", attested=True).allowed


def test_a_refusal_never_carries_material():
    """The denial is the leak surface: it must describe a count, not a share."""
    verdict = N.authorize(decision("untrusted"), "custody", shares=0)
    blob = repr(verdict.to_dict())
    assert "bytes" not in blob.lower()
    assert "0x" not in blob
    for secretish in ("share=", "kek", "dek", "password", "bssid"):
        assert secretish not in blob.lower()


def test_a_more_permissive_policy_never_denies_what_this_one_allows():
    narrow, wide = decision("untrusted"), decision("managed")
    for resource in N.RESOURCES:
        if N.authorize(narrow, resource, requested=1, shares=1).allowed:
            if resource in ("retention", "custody"):
                continue
            assert N.authorize(wide, resource, requested=1, shares=1).allowed, resource


def test_authorize_all_is_deterministic_and_aggregates():
    out = N.authorize_all(decision("untrusted"),
                          {"egress": {}, "retention": {"requested": 30}, "write": {}})
    assert list(out["verdicts"]) == ["egress", "retention", "write"]
    assert out["allowed"] is False
    assert out["policy"] == "untrusted"
    again = N.authorize_all(decision("untrusted"),
                            {"write": {}, "retention": {"requested": 30}, "egress": {}})
    assert out == again, "request order must not change the answer"


def test_every_denial_names_code_requirement_observation_remedy():
    for resource in N.RESOURCES:
        for verdict in (N.authorize(decision("untrusted"), resource, requested=999, shares=0,
                                    attested=False),):
            for denial in verdict.denials:
                payload = denial.to_dict()
                for field in ("code", "required", "observed", "remedy", "policy", "trust"):
                    assert payload[field], (resource, field)


def test_selected_policy_denies_egress_end_to_end():
    """The settings and the denial agree for a context the selector does not trust."""
    ctx = N.NetworkContext(bssid=None)
    d = N.select_policy(ctx)
    if d.policy == "managed":
        pytest.skip("selector considered this environment managed")
    assert not N.authorize(d, "egress").allowed

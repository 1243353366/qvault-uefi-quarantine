"""Threat intelligence: what the evidence supports, and what the doctrine refuses.

The tests are adversarial in the analyst's direction rather than the attacker's: they try to launder
one source into several, to promote a wallet to an owner, and to turn a rotation into an attribution.
"""
from __future__ import annotations

import hashlib

import pytest

from qvault.threatintel import (CLAIM_CEILINGS, GRADES, Assessor, DoctrineViolation,
                               IntelligenceError, Observation, deleted_domains_are_not_enough,
                               disruption_plan, evidence_package)


def obs(claim="infrastructure_relationship", subject="campaign-a", source="published_report",
        grade="CORROBORATED", entities=("domain:bad.example", "ip:203.0.113.9"),
        derived_from=(), note="") -> Observation:
    return Observation(claim, subject, source, grade, tuple(entities),
                       tuple(derived_from), note)


# ---------- doctrine ----------

@pytest.mark.parametrize("source", ["active_probe", "forced_rotation", "credential_use",
                                    "purchase", "wallet_interaction", "intrusion"])
def test_collection_sources_are_refused(source):
    with pytest.raises(DoctrineViolation):
        Assessor().add(obs(source=source))


def test_an_unknown_source_has_no_default():
    with pytest.raises(IntelligenceError):
        Assessor().add(obs(source="someone_told_me"))


def test_unknown_claims_and_entities_are_refused():
    with pytest.raises(IntelligenceError):
        Assessor().add(obs(claim="vibes"))
    with pytest.raises(IntelligenceError):
        Assessor().add(obs(entities=("person:someone",)))


# ---------- independence ----------

def test_four_rows_from_one_root_are_still_one_observation():
    a = Assessor()
    seed = a.add(obs(note="the vendor report"))
    derived = [a.add(obs(derived_from=(seed,), note=f"derived {i}")) for i in range(4)]
    result = a.grade(derived + [seed], "infrastructure_relationship")
    assert result["independent_roots"] == 1
    assert result["grade"] == "INFERRED"
    assert "one provenance root" in result["note"]


def test_two_independent_roots_corroborate():
    a = Assessor()
    one = a.add(obs(source="published_report"))
    two = a.add(obs(source="provider_disclosure", note="abuse ticket"))
    result = a.grade([one, two], "infrastructure_relationship")
    assert result["independent_roots"] == 2
    assert result["grade"] == "CORROBORATED"


def test_derivation_chain_is_followed_transitively():
    a = Assessor()
    seed = a.add(obs())
    mid = a.add(obs(derived_from=(seed,)))
    leaf = a.add(obs(derived_from=(mid,)))
    assert a.independence([leaf]) == 1


# ---------- ceilings ----------

def test_operator_attribution_never_exceeds_hypothesis():
    a = Assessor()
    ids = [a.add(obs(claim="operator_attribution", subject="alleged-op", grade="CONFIRMED",
                     source=src))
           for src in ("published_report", "provider_disclosure", "court_record")]
    result = a.grade(ids, "operator_attribution")
    assert result["grade"] == "HYPOTHESIS"
    assert result["ceiling"] == "HYPOTHESIS"


def test_a_wallet_does_not_become_an_owner():
    a = Assessor()
    ids = [a.add(obs(claim="wallet_ownership", subject="wallet:bc1qexample",
                     entities=("wallet:bc1qexample", "telegram_channel:t.me/x"), grade="CONFIRMED"))]
    assert a.grade(ids, "wallet_ownership")["grade"] == "HYPOTHESIS"


def test_a_proxy_fingerprint_does_not_identify_an_operator():
    a = Assessor()
    ids = [a.add(obs(claim="proxy_operator_attribution", entities=("proxy_service:exit-7",)))]
    assert a.grade(ids, "proxy_operator_attribution")["grade"] == "HYPOTHESIS"


def test_attribution_outputs_carry_no_identity_field():
    a = Assessor()
    a.add(obs(claim="operator_attribution", subject="alleged-op"))
    for hyp in a.attribution():
        assert "identity" not in hyp and "person" not in hyp
        assert hyp["never_establishes"] == "who controls the artefact"


def test_every_ceiling_is_a_real_grade():
    assert set(CLAIM_CEILINGS.values()) <= set(GRADES)


# ---------- infrastructure ----------

def test_graph_edges_keep_their_grade_and_source():
    a = Assessor()
    a.add(obs(source="blockchain_record", grade="INFERRED"))
    graph = a.graph()
    assert graph["edges"][0]["grade"] == "INFERRED"
    assert graph["edges"][0]["source"] == "blockchain_record"
    assert {n["kind"] for n in graph["nodes"]} == {"domain", "ip"}


def test_a_ledger_pointer_means_domain_blocks_are_not_a_fix():
    pointer = obs(claim="campaign_membership", entities=("sample_hash:deadbeef",
                                                         "smart_contract:0xabc"))
    result = deleted_domains_are_not_enough([pointer])
    assert result["blockchain_dependent"] is True
    assert result["domains_sufficient"] is False


def test_no_pointer_is_unknown_not_clean():
    result = deleted_domains_are_not_enough([obs()])
    assert result["grade"] == "UNKNOWN"
    assert "absence of evidence" in result["note"]


# ---------- reporting ----------

def test_disruption_is_reporting_only():
    plan = disruption_plan(["domain:bad.example", "wallet:bc1qexample", "telegram_channel:t.me/x"])
    assert {row["action"] for row in plan} <= {"report", "notify", "preserve", "submit"}
    wallet = next(row for row in plan if row["entity"].startswith("wallet:"))
    assert "exchange" in wallet["channel"]


def test_package_requires_a_competing_explanation():
    a = Assessor()
    a.add(obs(claim="operator_attribution", subject="alleged-op"))
    with pytest.raises(IntelligenceError, match="alternative"):
        evidence_package(a, case="c1", artifacts={"a.txt": b"x"}, alternatives={})


def test_package_hashes_artifacts_and_states_its_limits():
    a = Assessor()
    a.add(obs(claim="operator_attribution", subject="alleged-op"))
    package = evidence_package(a, case="c1", artifacts={"sample.bin": b"malware-bytes"},
                               alternatives={"operator_attribution": "a shared builder, not a shared operator"})
    digest = hashlib.sha256(b"malware-bytes").hexdigest()
    assert package["artifacts"][0]["sha256"] == digest
    assert package["hypotheses"][0]["grade"] == "HYPOTHESIS"
    assert any("who controls a wallet" in line for line in package["does_not_establish"])


def test_distinct_derivations_have_distinct_ids():
    """Regression: a derived observation once inherited its parent's id and the walk followed itself."""
    seed = obs(note="seed")
    child = obs(derived_from=("placeholder",), note="seed")
    assert seed.id != child.id


def test_a_derivation_cycle_is_refused_rather_than_followed():
    a = Assessor()
    seed = obs(note="loop")
    a._obs[seed.id] = seed.__class__(seed.claim, seed.subject, seed.source, seed.grade,
                                     seed.entities, (seed.id,), seed.note)
    with pytest.raises(IntelligenceError, match="cycle"):
        a.roots(seed.id)

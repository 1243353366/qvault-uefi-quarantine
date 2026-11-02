"""Policy semantics on the authorization boundary.

Everything here is black-box and reproducible: the same inputs must give the same shape,
an unknown resource must be indistinguishable from a forbidden one, a failure to evaluate
must deny, and a more permissive policy must never refuse something a stricter one allows.
"""
import itertools

import pytest

from qvault import netpolicy as N

RESOURCES = ("egress", "write", "collection", "retention", "custody", "attestation")
PROBE = ("egress", "custody", "some_made_up_resource", "", "retention")


def d(policy):
    return N.Decision(policy=policy, trust=policy)


OPERATOR = N.Principal(name="analyst", role="analysis", sees_detail=True)


# --- 1. refusals are constant-shaped ------------------------------------------------

@pytest.mark.parametrize("policy", sorted(N.POLICIES))
def test_every_refusal_has_the_same_public_shape(policy):
    refusals = {repr(a) for a in (N.authorize(d(policy), resource, requested=9999,
                                              shares=0, attested=False)
                                  for resource in PROBE) if not a["allowed"]}
    assert len(refusals) == 1, refusals


def test_hidden_counts_do_not_change_the_public_answer():
    """Counts below the threshold must all refuse identically; the count itself is hidden."""
    answers = {repr(N.authorize(d("untrusted"), "custody", shares=n)) for n in (0, 1, 2)}
    assert len(answers) == 1
    assert N.authorize(d("untrusted"), "custody", shares=3)["allowed"] is True


def test_the_public_taxonomy_has_exactly_one_code():
    codes = {N.authorize(d(p), r, shares=0, attested=False)["code"]
             for p in N.POLICIES for r in PROBE
             if not N.authorize(d(p), r, shares=0, attested=False)["allowed"]}
    assert codes == {N.PUBLIC_DENIAL_CODE}


# --- 2. unknown means deny, uniformly -------------------------------------------------

@pytest.mark.parametrize("policy", sorted(N.POLICIES))
def test_an_unknown_resource_is_denied_under_every_policy(policy):
    answer = N.authorize(d(policy), "no_such_thing")
    assert answer["allowed"] is False
    assert answer["code"] == N.PUBLIC_DENIAL_CODE


def test_unknown_is_indistinguishable_from_forbidden():
    denied = N.authorize(d("untrusted"), "egress")
    unknown = N.authorize(d("untrusted"), "no_such_thing")
    assert denied == unknown


def test_an_empty_resource_is_refused_not_crashed():
    assert N.authorize(d("managed"), "")["allowed"] is False


# --- 3. the reason is recorded for the owner -----------------------------------------

def test_the_reason_is_recorded_and_not_returned():
    seen = []
    answer = N.authorize(d("untrusted"), "egress", audit=seen.append)
    assert len(seen) == 1
    assert "DENY_EGRESS" in seen[0]["codes"]
    assert seen[0]["policy"] == "untrusted"
    assert "DENY_EGRESS" not in repr(answer)
    assert "egress" not in repr(answer)


def test_recording_does_not_alter_the_public_answer():
    without = N.authorize(d("untrusted"), "custody", shares=0)
    with_audit = N.authorize(d("untrusted"), "custody", shares=0, audit=lambda r: None)
    assert without == with_audit


# --- 4. fail closed ----------------------------------------------------------------

def test_an_evaluator_failure_denies(monkeypatch):
    def explode(*a, **k):
        raise RuntimeError("evaluator is broken")

    monkeypatch.setattr(N, "_evaluate", explode)
    answer = N.authorize(d("managed"), "egress")
    assert answer["allowed"] is False
    assert answer["code"] == N.PUBLIC_DENIAL_CODE


def test_failure_answer_matches_an_ordinary_refusal(monkeypatch):
    ordinary = N.authorize(d("untrusted"), "egress")

    def explode(*a, **k):
        raise RuntimeError("evaluator is broken")

    monkeypatch.setattr(N, "_evaluate", explode)
    assert N.authorize(d("managed"), "egress") == ordinary


def test_a_failure_is_recorded_by_type_and_not_by_message(monkeypatch):
    seen = []

    def explode(*a, **k):
        raise RuntimeError("secret-token-should-not-escape")

    monkeypatch.setattr(N, "_evaluate", explode)
    answer = N.authorize(d("managed"), "egress", audit=seen.append)
    assert seen[0]["error"] == "RuntimeError"
    assert "secret-token" not in repr(seen)
    assert "secret-token" not in repr(answer)


def test_an_operator_sees_that_the_evaluator_failed(monkeypatch):
    def explode(*a, **k):
        raise RuntimeError("broken")

    monkeypatch.setattr(N, "_evaluate", explode)
    answer = N.authorize(d("managed"), "egress", principal=OPERATOR)
    assert answer["denials"][0]["code"] == "DENY_EVALUATION_ERROR"
    assert answer["denials"][0]["remedy"]


# --- 5. monotonicity ----------------------------------------------------------------

def test_managed_is_at_least_as_permissive_as_every_other_policy():
    for other in N.POLICIES:
        if other != "hostile":
            assert N.at_least_as_permissive("managed", other), other


REQUESTS = [
    {"resource": "egress"}, {"resource": "write"}, {"resource": "attestation"},
    {"resource": "attestation", "attested": True},
] + [{"resource": "collection", "requested": level}
     for level in ("minimal", "standard", "forensic")] \
  + [{"resource": "retention", "requested": days} for days in (1, 7, 30, 90, 365, 366)] \
  + [{"resource": "custody", "shares": n} for n in range(0, 6)]


@pytest.mark.parametrize("a,b", list(itertools.permutations(sorted(N.POLICIES), 2)))
def test_a_more_permissive_policy_never_refuses_what_a_stricter_one_allows(a, b):
    if not N.at_least_as_permissive(a, b):
        pytest.skip(f"{a} does not dominate {b}")
    for request in REQUESTS:
        kwargs = {k: v for k, v in request.items() if k != "resource"}
        strict = N._evaluate(d(b), request["resource"], **kwargs)
        if strict.allowed:
            assert N._evaluate(d(a), request["resource"], **kwargs).allowed, (a, b, request)


def test_adding_requests_to_a_batch_cannot_turn_a_denial_into_an_allow():
    small = {"egress": {}}
    large = {"egress": {}, "retention": {"requested": 999}}
    assert N.authorize_all(d("untrusted"), small, principal=OPERATOR)["allowed"] is False
    assert N.authorize_all(d("untrusted"), large, principal=OPERATOR)["allowed"] is False
    allowed_batch = {"egress": {}}
    assert N.authorize_all(d("managed"), allowed_batch, principal=OPERATOR)["allowed"] is True


def test_an_unknown_policy_is_refused_rather_than_defaulted():
    with pytest.raises(KeyError):
        N.allowance("totally_trusted")

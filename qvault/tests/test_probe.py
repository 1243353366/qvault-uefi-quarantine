"""The probe contract, tested as a contract.

Each test corresponds to a way a probe can stop being an instrument and become an attack
surface: an oracle, a remote execution path, a resource burden, or a retry loop.
"""
import inspect
import time

import pytest

from qvault import netpolicy as N
from qvault import probe as P


def d(policy="untrusted"):
    return N.Decision(policy=policy, trust=policy)


# --- non-oracular --------------------------------------------------------------------

def test_different_secret_resources_give_the_same_public_token():
    probe = P.Probe(d(), budget=P.Budget(max_calls=50))
    hidden = ["egress", "a_real_but_forbidden_resource", "no_such_thing", "x" * 200]
    answers = {probe.ask(r) for r in hidden}
    assert answers == {P.DENY}


def test_a_forbidden_resource_and_a_missing_one_are_indistinguishable():
    assert P.observe(d(), "egress") == P.observe(d(), "no_such_thing")


def test_the_vocabulary_is_closed():
    probe = P.Probe(d(), budget=P.Budget(max_calls=20))
    answers = {probe.ask(r) for r in ("egress", "", None, 42, "nope")}
    assert answers <= set(P.TOKENS)


def test_an_allowed_resource_is_not_distinguishable_from_a_denied_one_by_shape():
    """Both are a bare token: the caller learns the decision, not the machinery."""
    allowed = P.observe(d("managed"), "egress")
    denied = P.observe(d("managed"), "retention")
    assert isinstance(allowed, str) and isinstance(denied, str)
    assert len(allowed) == len(P.ALLOW) or allowed == P.ALLOW


# --- bounded and single-shot ---------------------------------------------------------

def test_a_second_call_gives_unknown_not_another_attempt():
    probe = P.Probe(d())
    assert probe.ask("egress") == P.DENY
    assert probe.ask("egress") == P.UNKNOWN
    assert probe.calls == 1


def test_the_budget_can_allow_a_fixed_number_of_calls():
    probe = P.Probe(d(), budget=P.Budget(max_calls=3))
    assert [probe.ask("egress") for _ in range(4)] == [P.DENY, P.DENY, P.DENY, P.UNKNOWN]


def test_a_slow_evaluation_fails_closed_to_unknown():
    ticks = iter([0.0, 10.0])
    probe = P.Probe(d(), budget=P.Budget(max_seconds=0.05), clock=lambda: next(ticks))
    assert probe.ask("egress") == P.UNKNOWN


def test_there_is_no_retry_when_evaluation_raises(monkeypatch):
    calls = []

    def explode(*a, **k):
        calls.append(1)
        raise RuntimeError("boom")

    monkeypatch.setattr(N, "_evaluate", explode)
    assert P.observe(d(), "egress") == P.UNKNOWN
    assert len(calls) == 1


# --- fail closed on ambiguity --------------------------------------------------------

@pytest.mark.parametrize("bad", ["", None, 42, [], {}])
def test_malformed_input_is_refused_not_crashed(bad):
    assert P.observe(d(), bad) == P.DENY


def test_incomplete_context_is_partial_not_absent():
    probe = P.Probe(d("managed"))
    result = probe.context()
    assert result["verdict"] == P.PARTIAL
    assert P.UNKNOWN in result["gates"].values()
    assert "absent" not in repr(result).lower()


def test_missing_attestation_outranks_a_denial():
    """An unestablished evidence class makes the question unanswerable, not answered no."""
    result = P.Probe(d()).context(attested=None, shares=3, days=7, collection="minimal")
    assert result["verdict"] == P.UNATTESTED
    assert result["gates"]["attestation"] == P.UNKNOWN
    assert result["gates"]["egress"] == P.DENY, "the denial is still visible in the gates"


def test_a_complete_context_answers_allow_or_deny():
    ok = P.Probe(d("managed")).context(attested=True, shares=3, days=30, collection="minimal")
    assert ok["verdict"] == P.ALLOW
    bad = P.Probe(d("untrusted")).context(attested=True, shares=3, days=7,
                                          collection="minimal")
    assert bad["verdict"] == P.DENY


def test_context_labels_are_gate_names_and_never_resources():
    result = P.Probe(d()).context(attested=True, shares=3, days=7, collection="minimal")
    assert set(result["gates"]) == set(N.RESOURCES)
    assert "DENY_" not in repr(result)


# --- passive: no execution, no side effects, no remote work ---------------------------

def test_the_probe_imports_nothing_that_can_reach_out():
    source = inspect.getsource(P)
    for forbidden in ("socket", "urllib", "http.client", "requests", "subprocess",
                      "os.system", "eval(", "exec(", "open("):
        assert forbidden not in source, forbidden


def test_probing_leaves_policy_state_untouched():
    before = repr(sorted((k, sorted(v.items())) for k, v in N.POLICIES.items()))
    for resource in ("egress", "retention", "custody", "made_up"):
        P.observe(d(), resource)
    P.Probe(d("managed")).context(attested=True, shares=3, days=30, collection="minimal")
    after = repr(sorted((k, sorted(v.items())) for k, v in N.POLICIES.items()))
    assert before == after


def test_probing_creates_no_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    P.observe(d(), "egress")
    P.Probe(d()).context()
    assert list(tmp_path.iterdir()) == []


# --- work and timing do not vary with the hidden answer ------------------------------

def test_every_gate_is_evaluated_whatever_is_asked():
    for resource in ("egress", "no_such_thing", ""):
        assert N.evaluation_trace(d(), resource) == N.RESOURCES


def test_the_answer_does_not_take_a_cheaper_path_for_unknown_resources():
    probe = P.Probe(d(), budget=P.Budget(max_calls=400))
    resources = ["egress", "no_such_thing"] * 100
    timings = {"egress": [], "no_such_thing": []}
    for resource in resources:
        started = time.perf_counter()
        probe.ask(resource)
        timings[resource].append(time.perf_counter() - started)
    known = sum(timings["egress"])
    unknown = sum(timings["no_such_thing"])
    ratio = max(known, unknown) / max(min(known, unknown), 1e-9)
    assert ratio < 3.0, f"timing differs by {ratio:.2f}x between known and unknown"


# --- monotonicity holds through the probe too ---------------------------------------

@pytest.mark.parametrize("a,b", [("managed", "untrusted"), ("managed", "ambiguous")])
def test_a_more_permissive_policy_probe_is_never_stricter(a, b):
    for resource in N.RESOURCES:
        if P.observe(d(b), resource, ) == P.ALLOW:
            assert P.observe(d(a), resource) in (P.ALLOW, P.UNKNOWN)

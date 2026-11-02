"""The wire contract, and the boundary that keeps the engine single-owner.

The point of these tests is that language diversity cannot quietly move the decision: an
adapter in another runtime can read the contract, and the contract has no field in which to
carry a hidden fact.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qvault import contract as C
from qvault import findings as F
from qvault import netpolicy as N
from qvault import persistence as P

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "contract" / "verdict.schema.json").read_text())
LINT = ROOT / "adapters" / "verdict_lint.mjs"


def persistence_result(**kw):
    kw.setdefault("basis", "offline_image")
    return P.assess([P.AutostartEntry("run_key", "x", "C:\\Temp\\a.exe", signed=False)], **kw)


def refusal():
    return C.from_policy_answer(
        N.authorize(N.Decision(policy="untrusted", trust=N.UNTRUSTED), "egress"))


# --- the schema and the code agree ---------------------------------------------------

def test_the_schema_declares_every_field_the_builder_emits():
    built = C.Verdict(layer=C.POLICY, verdict="refused", remedy="r").to_wire()
    assert set(SCHEMA["required"]) == set(built)
    assert set(SCHEMA["properties"]) == set(built)


def test_code_enums_match_the_schema_enums():
    props = SCHEMA["properties"]
    assert set(props["layer"]["enum"]) == set(C.LAYERS)
    assert set(props["verdict"]["enum"]) == set(C.VERDICTS)
    assert set(props["cap_grade"]["enum"]) == set(C.GRADES) | {None}
    assert set(props["basis"]["enum"]) == set(C.BASES) | {None}
    assert set(props["attestation_state"]["enum"]) == set(C.ATTESTATION_STATES) | {None}
    assert set(props["denial_codes"]["items"]["enum"]) == set(C.DENIAL_CODES)


def test_the_public_denial_vocabulary_has_exactly_one_code():
    assert C.DENIAL_CODES == ("policy_denied",)


# --- persistence payloads ------------------------------------------------------------

def test_every_matrix_row_becomes_a_valid_payload():
    result = persistence_result()
    payloads = C.from_persistence_result(result)
    assert len(payloads) == len(P.MECHANISMS)
    for payload in payloads:
        assert C.validate(payload) == []


def test_a_persistence_payload_carries_its_basis_and_grade():
    payload = next(p for p in C.from_persistence_result(persistence_result())
                   if p["verdict"] == "detected")
    assert payload["basis"] == "offline_image"
    assert payload["cap_grade"] == F.INFERRED
    assert payload["denial_codes"] == []


def test_a_persistence_verdict_may_not_be_clean():
    payload = dict(C.from_persistence_result(persistence_result())[0])
    payload["verdict"] = "clean"
    problems = C.validate(payload)
    assert any("not a persistence verdict" in p for p in problems)


def test_a_persistence_payload_needs_a_basis():
    payload = dict(C.from_persistence_result(persistence_result())[0])
    payload["basis"] = None
    assert any("collection basis" in p for p in C.validate(payload))


def test_a_persistence_payload_may_not_carry_denial_codes():
    payload = dict(C.from_persistence_result(persistence_result())[0])
    payload["denial_codes"] = ["policy_denied"]
    assert any("no denial codes" in p for p in C.validate(payload))


# --- the oracle guarantee, at the type level ----------------------------------------

def test_a_policy_refusal_does_not_carry_the_resource():
    assert refusal()["subject"]["resource"] is None


def test_a_policy_payload_that_echoes_a_resource_is_rejected():
    payload = dict(refusal())
    payload["subject"] = {"mechanism": None, "resource": "egress"}
    problems = C.validate(payload)
    assert any("may not echo the resource" in p for p in problems)


def test_a_denial_code_outside_the_public_vocabulary_is_rejected():
    payload = dict(refusal())
    payload["denial_codes"] = ["DENY_EGRESS"]
    assert any("outside the public vocabulary" in p for p in C.validate(payload))


def test_an_allow_carries_no_denial_code():
    payload = dict(refusal())
    payload["verdict"] = "allow"
    assert any("only a refusal" in p for p in C.validate(payload))


def test_a_policy_answer_cannot_claim_an_evidence_grade():
    payload = dict(refusal())
    payload["basis"] = "offline_image"
    assert any("authorisation result" in p for p in C.validate(payload))


# --- structural refusals -------------------------------------------------------------

def test_a_payload_without_a_remedy_is_refused():
    payload = dict(refusal())
    payload.pop("remedy")
    assert any("missing field remedy" in p for p in C.validate(payload))


def test_an_unexpected_field_is_refused():
    payload = dict(refusal())
    payload["observed_resource"] = "egress"
    assert any("unexpected fields" in p for p in C.validate(payload))


def test_a_negative_or_boolean_entry_count_is_refused():
    for bad in (-1, True):
        payload = dict(refusal())
        payload["observed"] = {"signals": [], "entries": bad, "coverage": None}
        assert any("non-negative integer" in p for p in C.validate(payload))


def test_assert_valid_raises_with_the_reason():
    with pytest.raises(C.ContractError) as err:
        C.assert_valid({"kind": "verdict"})
    assert "missing field" in str(err.value)


# --- single owner --------------------------------------------------------------------

def test_the_decision_has_one_owner_in_one_runtime():
    C.assert_single_owner()


def test_the_engine_does_not_import_an_adapter():
    source = (ROOT / "qvault" / "netpolicy.py").read_text()
    for adapter in ("persistence", "probe", "contract"):
        assert f"from . import {adapter}" not in source


def test_the_owner_check_would_catch_a_delegated_decision(monkeypatch):
    """Prove the check has teeth: forbid a token the engine really contains."""
    monkeypatch.setattr(C, "_FORBIDDEN_IN_ENGINE", ("def ",))
    with pytest.raises(C.ContractError) as err:
        C.assert_single_owner()
    assert "must stay in-process" in str(err.value) or "may not use" in str(err.value)


# --- the other runtime ---------------------------------------------------------------

needs_node = pytest.mark.skipif(not (shutil.which("node") and LINT.exists()),
                                reason="node adapter unavailable")


@needs_node
def test_a_second_runtime_accepts_a_valid_payload(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps(refusal()))
    done = subprocess.run(["node", str(LINT), str(path)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


@needs_node
def test_a_second_runtime_rejects_a_broken_payload(tmp_path):
    payload = refusal()
    payload.pop("remedy")
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload))
    done = subprocess.run(["node", str(LINT), str(path)], capture_output=True, text=True)
    assert done.returncode != 0
    assert "remedy" in done.stderr


# --- gates as evidence ---------------------------------------------------------------

def _gates():
    sys.path.insert(0, str(ROOT / "tools"))
    import gates  # noqa: PLC0415 - local import keeps the tool out of the package
    return gates


def test_the_fast_gates_pass():
    gates = _gates()
    for gid, name, check in gates.GATES:
        if gid in ("G1", "G2", "G3"):
            continue                     # the slow gates, run by tools/gates.py
        ok, detail = check()
        assert ok, f"{gid} {name}: {detail}"


def test_every_gate_is_named_and_callable():
    gates = _gates()
    assert [g[0] for g in gates.GATES] == [f"G{i}" for i in range(1, len(gates.GATES) + 1)]
    assert all(callable(g[2]) for g in gates.GATES)

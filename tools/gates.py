#!/usr/bin/env python3
"""Pre-merge gates. Evidence-based acceptance, in the order the sprint ends.

Scrum runs the backlog; these gates decide whether a change may merge. Velocity does not
override them: a gate that fails is a refusal, not a delay to be argued down.

  G1 unit tests          the suite passes
  G2 smoke               the end-to-end lifecycle still works
  G3 evidence ledger     every claim has a source, a tag, a status and a falsifier
  G4 contract            both layers emit payloads the schema accepts, in Python and in node
  G5 single owner        the decision has one owner, in one runtime, and does not shell out
  G6 no clean state      the persistence layer cannot report a clean result
  G7 denial invariance   a refusal does not vary with the resource that was asked for
  G8 scope gate          a live capture is refused without isolation and attestation

Usage: python3 tools/gates.py [--list] [G4 G7]
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _run(argv) -> tuple[bool, str]:
    completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    tail = (completed.stdout or completed.stderr).strip().splitlines()
    return completed.returncode == 0, (tail[-1] if tail else "")


def g1_tests() -> tuple[bool, str]:
    return _run([sys.executable, "-m", "pytest", "qvault/tests", "-q"])


def g2_smoke() -> tuple[bool, str]:
    return _run([sys.executable, "tools/smoke.py"])


def g3_ledger() -> tuple[bool, str]:
    return _run([sys.executable, "tools/check_claims.py"])


def _samples() -> list[dict]:
    from qvault import contract as C
    from qvault import netpolicy as N
    from qvault import persistence as P

    result = P.assess([P.AutostartEntry("run_key", "x", "C:\\Temp\\a.exe", signed=False),
                       P.AutostartEntry("boot_execute", "b", "autocheck autochk * \\x.sys")],
                      basis="offline_image")
    payloads = C.from_persistence_result(result)
    decision = N.Decision(policy="untrusted", trust=N.UNTRUSTED)
    payloads.append(C.from_policy_answer(N.authorize(decision, "egress")))
    return payloads


def g4_contract() -> tuple[bool, str]:
    """Both layers, validated by the Python contract and, when present, by node."""
    from qvault import contract as C

    payloads = _samples()
    for payload in payloads:
        problems = C.validate(payload)
        if problems:
            return False, f"invalid payload: {problems[0]}"

    node = shutil.which("node")
    adapter = ROOT / "adapters" / "verdict_lint.mjs"
    if not node or not adapter.exists():
        return True, f"{len(payloads)} payloads valid in python (node absent, adapter skipped)"

    with tempfile.TemporaryDirectory() as tmp:
        for index, payload in enumerate(payloads):
            path = Path(tmp) / f"p{index}.json"
            path.write_text(json.dumps(payload))
            ok, message = _run([node, str(adapter), str(path)])
            if not ok:
                return False, f"node rejected payload {index}: {message}"
        # the adapter must also reject a broken payload, or it proves nothing
        broken = dict(payloads[-1]); broken.pop("remedy")
        path = Path(tmp) / "broken.json"
        path.write_text(json.dumps(broken))
        ok, _ = _run([node, str(adapter), str(path)])
        if ok:
            return False, "node accepted a payload with no remedy"
    return True, f"{len(payloads)} payloads valid in python and node, broken payload rejected"


def g5_single_owner() -> tuple[bool, str]:
    from qvault import contract as C

    C.assert_single_owner()
    return True, f"engine {len(C.ENGINE_MODULES)} modules, adapters {len(C.ADAPTER_MODULES)}"


def g6_no_clean() -> tuple[bool, str]:
    from qvault import contract as C
    from qvault import persistence as P

    if P.CLEAN_STATES:
        return False, "the persistence layer declares clean states"
    for verdict in C.FORBIDDEN_PERSISTENCE_VERDICTS:
        if verdict in C.PERSISTENCE_VERDICTS:
            return False, f"{verdict} is an allowed persistence verdict"
    from qvault import findings as F
    empty = P.assess([], basis="offline_image")
    if any(row["grade"] != F.UNKNOWN for row in empty["matrix"]):
        return False, "an empty snapshot produced a graded finding"
    return True, "no clean state, and an empty snapshot grades nothing"


def g7_denial_invariance() -> tuple[bool, str]:
    from qvault import contract as C
    from qvault import netpolicy as N

    decision = N.Decision(policy="untrusted", trust=N.UNTRUSTED)
    shapes = set()
    refusals = 0
    for resource in ("egress", "custody", "a_resource_that_does_not_exist", "", "retention"):
        payload = C.from_policy_answer(N.authorize(decision, resource, shares=0))
        if payload["verdict"] != "refused":
            continue                       # an allow is a decision, not a refusal to compare
        refusals += 1
        shapes.add(json.dumps(payload, sort_keys=True))
    if refusals < 2:
        return False, "not enough refusals in the sweep to compare"
    if len(shapes) != 1:
        return False, f"refusal varies with the resource asked for ({len(shapes)} shapes)"
    return True, f"{refusals} refusals, identical across forbidden, absent and empty resources"


def g8_scope() -> tuple[bool, str]:
    from qvault import persistence as P
    from qvault import separation as S

    try:
        P.assess([], scope=S.LIVE_CAPTURE)
    except S.ScopeError:
        return True, "a live capture is refused without isolation and attestation"
    return False, "a live capture was permitted"


GATES = (
    ("G1", "unit tests", g1_tests),
    ("G2", "smoke", g2_smoke),
    ("G3", "evidence ledger", g3_ledger),
    ("G4", "wire contract", g4_contract),
    ("G5", "single owner", g5_single_owner),
    ("G6", "no clean state", g6_no_clean),
    ("G7", "denial invariance", g7_denial_invariance),
    ("G8", "scope gate", g8_scope),
)


def main(argv: list[str]) -> int:
    if "--list" in argv:
        for gid, name, _ in GATES:
            print(f"{gid}  {name}")
        return 0

    wanted = {a.upper() for a in argv if a.upper().startswith("G")}
    failures = 0
    for gid, name, check in GATES:
        if wanted and gid not in wanted:
            continue
        try:
            ok, detail = check()
        except Exception as exc:                     # noqa: BLE001 - a broken gate is a fail
            ok, detail = False, f"gate raised {type(exc).__name__}: {exc}"
        print(f"{'PASS' if ok else 'FAIL'}  {gid}  {name:18} {detail}")
        failures += 0 if ok else 1
    print(f"\n{'ALL GATES PASS' if not failures else f'{failures} GATE(S) FAILED'}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

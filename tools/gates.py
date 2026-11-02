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
  G9 behaviour matrix    every behaviour resolves to real code and the document is current
  G10 telemetry map      every mechanism has an evidence source or a stated reason
  G11 in-the-wild set    the pinned reference set is intact and its report is current
  G12 documentation site the published site is a current render of the repository
  G13 version source     the version has one source and every copy agrees with it
  G14 internal links     every link in the published site resolves
  G15 residency taxonomy substrate per family, and no document merges them
  G16 table alignment     columns line up in the source, not only when rendered
  G17 denial model        every posture keeps its non-claims; no denial reaches CONFIRMED

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


def g9_behaviour_matrix() -> tuple[bool, str]:
    """Every behaviour resolves to real code, and the generated document is current."""
    from qvault import behaviors as B

    B.assert_resolves()
    sys.path.insert(0, str(ROOT / "tools"))
    import tables  # noqa: PLC0415
    import gen_behavior_matrix  # noqa: PLC0415

    on_disk = (ROOT / "report" / "THREAT_BEHAVIOR_MATRIX.md").read_text()
    if on_disk != tables.align(gen_behavior_matrix.render()):
        return False, "report/THREAT_BEHAVIOR_MATRIX.md is stale; run tools/gen_behavior_matrix.py"
    gaps = len(B.gaps())
    return True, f"{len(B.BEHAVIOURS)} behaviours resolve, {gaps} declared gaps, document current"


def g8_scope() -> tuple[bool, str]:
    from qvault import persistence as P
    from qvault import separation as S

    try:
        P.assess([], scope=S.LIVE_CAPTURE)
    except S.ScopeError:
        return True, "a live capture is refused without isolation and attestation"
    return False, "a live capture was permitted"


def g10_telemetry() -> tuple[bool, str]:
    """Every mechanism has an evidence source or a stated reason, and the map is current."""
    from qvault import telemetry as T

    T.assert_complete()
    sys.path.insert(0, str(ROOT / "tools"))
    import tables  # noqa: PLC0415
    import gen_telemetry_map  # noqa: PLC0415

    on_disk = (ROOT / "report" / "TELEMETRY_MAP.md").read_text()
    if on_disk != tables.align(gen_telemetry_map.render()):
        return False, "report/TELEMETRY_MAP.md is stale; run tools/gen_telemetry_map.py"
    blind = T.mechanisms_without_host_evidence()
    return True, (f"{len(T.MECHANISM_SOURCES)} mechanisms mapped to {len(T.SOURCES)} sources, "
                  f"{len(blind)} with no host telemetry, map current")


def g11_in_the_wild() -> tuple[bool, str]:
    """The pinned reference set is intact, and the report on it is current."""
    from qvault import wild as W

    W.assert_dataset_integrity()
    sys.path.insert(0, str(ROOT / "tools"))
    import tables  # noqa: PLC0415
    import gen_in_the_wild  # noqa: PLC0415

    on_disk = (ROOT / "report" / "IN_THE_WILD.md").read_text()
    if on_disk != tables.align(gen_in_the_wild.render()):
        return False, "report/IN_THE_WILD.md is stale; run tools/gen_in_the_wild.py"
    summary = W.summary()
    return True, (f"{summary['entries']} entries pinned at {W.load()['source']['commit'][:8]}, "
                  f"report current")


def g12_documentation_site() -> tuple[bool, str]:
    """The published site is a current render of the repository."""
    sys.path.insert(0, str(ROOT / "tools"))
    import build_docs  # noqa: PLC0415

    stale = []
    for src, slug, title, _section in build_docs.PAGES:
        if not (ROOT / src).exists():
            stale.append(f"{src} missing")
            continue
        if not (ROOT / "docs" / slug).exists():
            stale.append(f"docs/{slug} missing")
            continue
        if (ROOT / "docs" / slug).read_text() != build_docs.render_page(src, slug, title):
            stale.append(f"docs/{slug} stale")
    if (ROOT / "CITATIONS.md").read_text() != build_docs.render_citations():
        stale.append("CITATIONS.md stale")
    if stale:
        return False, "; ".join(stale[:4]) + ("; run tools/build_docs.py")
    entries = len(build_docs.bibliography())
    return True, f"{len(build_docs.PAGES)} pages current, {entries} sources cited"


def g13_version_single_sourced() -> tuple[bool, str]:
    """One source of truth for the version, and every copy agrees with it."""
    sys.path.insert(0, str(ROOT / "tools"))
    import sync_version  # noqa: PLC0415

    want = sync_version.source_version()
    drift = [f"{name}={got}" for name, got in sync_version.claimed() if got != want]
    if sync_version.cli_version() != want:
        drift.append("qvault --version disagrees")
    if drift:
        return False, f"{want}: " + ", ".join(drift) + " (run tools/sync_version.py --write)"
    return True, f"{want} in source, README, packaging and CLI"


def g14_internal_links() -> tuple[bool, str]:
    """Every link in the published site resolves. No network, so it is safe to gate on."""
    sys.path.insert(0, str(ROOT / "tools"))
    import linkcheck  # noqa: PLC0415

    problems = linkcheck.check_internal()
    if problems:
        return False, "; ".join(problems[:3])
    return True, (f"{len(linkcheck.internal_links())} links resolve across "
                  f"{len(linkcheck.published())} pages")


def g15_residency() -> tuple[bool, str]:
    """Three implants, two substrates: the catalogue, the docs and the prose must agree."""
    from qvault import fingerprints as F  # noqa: PLC0415
    from qvault import residency as R  # noqa: PLC0415

    R.assert_taxonomy()
    problems = [f"{f} has no residency entry" for f in F.FAMILIES if f not in R.RESIDENCY]
    problems += [f"{f} is in the taxonomy but not the catalogue"
                 for f in R.RESIDENCY if f not in F.FAMILIES]

    for path in [ROOT / "README.md"] + sorted((ROOT / "report").glob("*.md")):
        for sentence in R.conflation_claims(path.read_text()):
            problems.append(f"{path.name}: conflates substrate: {sentence[:70]}")

    page = ROOT / "report" / "ACQUISITION_AND_ANALYSIS.md"
    if not page.exists():
        problems.append("acquisition page is missing")
    else:
        rows_in_page = []
        for line in page.read_text().splitlines():
            if line.strip().startswith("|"):
                rows_in_page.append(tuple(c.strip() for c in line.strip().strip("|").split("|")))
        for row in R.summary_rows():
            want = (row["family"], row["substrate"], row["hardware"])
            if not any(got[:3] == want for got in rows_in_page):
                problems.append(f"acquisition page has a stale row for {row['family']}")

    if problems:
        return False, "; ".join(problems[:3])
    esp = sum(1 for r in R.RESIDENCY.values() if not r.hardware_resident)
    return True, (f"{len(R.RESIDENCY)} families, {esp} not hardware-resident, "
                  f"no document merges them")


def g16_table_alignment() -> tuple[bool, str]:
    """Tables line up in the source, which is what a diff reader sees."""
    sys.path.insert(0, str(ROOT / "tools"))
    import tables  # noqa: PLC0415

    problems, total = [], 0
    for path in [ROOT / "README.md"] + sorted((ROOT / "report").glob("*.md")):
        text = path.read_text()
        total += text.count("\n|")
        bad = tables.misaligned(text)
        if bad:
            problems.append(f"{path.name}:{bad[0]}")
    if problems:
        return False, "; ".join(problems[:3]) + " (run tools/fix_tables.py --write)"
    return True, f"{total} table rows aligned across {len(list((ROOT / 'report').glob('*.md'))) + 1} documents"


def g17_denial_model() -> tuple[bool, str]:
    """Every posture keeps its non-claims, and no denial claim reaches CONFIRMED."""
    from qvault import denial as D, findings as F

    D.assert_complete()
    sys.path.insert(0, str(ROOT / "tools"))
    import tables  # noqa: PLC0415
    import gen_denial_model  # noqa: PLC0415

    for posture in D.POSTURES:
        for plane in D.PLANES:
            if plane not in posture.admissible_planes:
                continue
            for evidence in range(0, 6):
                for enforced in (True, False):
                    grade = D.assess(posture.name, plane=plane,
                                     corroborating_evidence=evidence,
                                     enforced_by_target=enforced)["grade"]
                    if grade == F.CONFIRMED:
                        return False, f"{posture.name} on {plane} reaches CONFIRMED"

    on_disk = (ROOT / "report" / "DENIAL_MODEL.md").read_text()
    if on_disk != tables.align(gen_denial_model.render()):
        return False, "report/DENIAL_MODEL.md is stale; run tools/gen_denial_model.py"
    for posture in D.POSTURES:
        if f"`{posture.name}`" not in on_disk:
            return False, f"{posture.name} is missing from the rendered model"
    return True, f"{len(D.POSTURES)} postures, {len(D.PLANES)} planes, no CONFIRMED denial claim"


GATES = (
    ("G1", "unit tests", g1_tests),
    ("G2", "smoke", g2_smoke),
    ("G3", "evidence ledger", g3_ledger),
    ("G4", "wire contract", g4_contract),
    ("G5", "single owner", g5_single_owner),
    ("G6", "no clean state", g6_no_clean),
    ("G7", "denial invariance", g7_denial_invariance),
    ("G8", "scope gate", g8_scope),
    ("G9", "behaviour matrix", g9_behaviour_matrix),
    ("G10", "telemetry map", g10_telemetry),
    ("G11", "in-the-wild set", g11_in_the_wild),
    ("G12", "documentation site", g12_documentation_site),
    ("G13", "version source", g13_version_single_sourced),
    ("G14", "internal links", g14_internal_links),
    ("G15", "residency taxonomy", g15_residency),
    ("G16", "table alignment", g16_table_alignment),
    ("G17", "denial model", g17_denial_model),
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

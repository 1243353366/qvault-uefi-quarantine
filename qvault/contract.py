"""The wire contract between the verdict engine and everything else.

The rule this file enforces: the decision is single-language and single-owner, and other
runtimes participate only by consuming a payload described in `contract/verdict.schema.json`.
Nothing here decides anything. It converts a decision that already exists into a shape that a
Go collector, a shell report generator or a JavaScript linter can read without ever holding
the policy logic.

Two properties are structural rather than conventional:

- A policy refusal has no field in which to carry the resource a caller asked about, so a
  refusal cannot become a probe about what exists.
- `denial_codes` is a closed vocabulary with exactly one public value, so an adapter cannot
  invent a richer taxonomy that partitions resources by which gate was nearly passing.
"""

from dataclasses import dataclass, field

from . import findings as F

SCHEMA_VERSION = "1.0"
SCHEMA_PATH = "contract/verdict.schema.json"

PERSISTENCE = "persistence"
POLICY = "policy"
LAYERS = (PERSISTENCE, POLICY)

#: The two layers that may produce a verdict. Everything else consumes the wire format.
ENGINE_MODULES = ("qvault.netpolicy", "qvault.grading")
ADAPTER_MODULES = ("qvault.persistence", "qvault.probe", "qvault.contract")

PERSISTENCE_VERDICTS = ("detected", "benign", "unknown_not_observable", "not_observed")
POLICY_VERDICTS = ("allow", "refused", "unknown", "partial", "unattested")
VERDICTS = PERSISTENCE_VERDICTS + POLICY_VERDICTS

BASES = ("synthetic", "live_host", "offline_image", "attested_image")
ATTESTATION_STATES = ("verified", "absent", "unknown")
GRADES = tuple(F.GRADES)

#: One public code. Deliberately not extensible per call site.
DENIAL_CODES = ("policy_denied",)

#: Tokens that may never appear as a verdict for a layer that observes an autostart surface.
FORBIDDEN_PERSISTENCE_VERDICTS = ("clean",)


class ContractError(ValueError):
    """Raised when a payload would break the contract between layers."""


@dataclass(frozen=True)
class Verdict:
    """One wire payload. Built here so no adapter invents its own shape."""

    layer: str
    verdict: str
    remedy: str
    statement: str = ""
    mechanism: str | None = None
    resource: str | None = None
    basis: str | None = None
    attestation_state: str | None = None
    signals: tuple[str, ...] = ()
    entries: int = 0
    coverage: dict | None = None
    cap_grade: str | None = None
    denial_codes: tuple[str, ...] = field(default_factory=tuple)

    def to_wire(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "verdict",
            "layer": self.layer,
            "subject": {"mechanism": self.mechanism, "resource": self.resource},
            "basis": self.basis,
            "attestation_state": self.attestation_state,
            "observed": {"signals": list(self.signals), "entries": int(self.entries),
                         "coverage": self.coverage},
            "verdict": self.verdict,
            "cap_grade": self.cap_grade,
            "denial_codes": list(self.denial_codes),
            "remedy": self.remedy,
            "statement": self.statement,
        }


def validate(payload: dict) -> list[str]:
    """Structural and cross-field checks, no external dependency.

    Returns a list of problems; an empty list means the payload conforms.
    """
    problems: list[str] = []
    required = ("schema_version", "kind", "layer", "subject", "basis", "attestation_state",
                "observed", "verdict", "cap_grade", "denial_codes", "remedy", "statement")
    for key in required:
        if key not in payload:
            problems.append(f"missing field {key}")
    if problems:
        return problems

    unexpected = set(payload) - set(required)
    if unexpected:
        problems.append(f"unexpected fields: {sorted(unexpected)}")

    if payload["schema_version"] != SCHEMA_VERSION:
        problems.append(f"schema_version must be {SCHEMA_VERSION!r}")
    if payload["kind"] != "verdict":
        problems.append("kind must be 'verdict'")

    layer = payload["layer"]
    if layer not in LAYERS:
        return problems + [f"layer {layer!r} is not one of {LAYERS}"]

    subject = payload["subject"]
    if not isinstance(subject, dict) or "mechanism" not in subject or "resource" not in subject:
        problems.append("subject must carry mechanism and resource")
        subject = {"mechanism": None, "resource": None}

    observed = payload["observed"]
    if not isinstance(observed, dict):
        problems.append("observed must be an object")
        observed = {"signals": [], "entries": 0, "coverage": None}
    for key in ("signals", "entries", "coverage"):
        if key not in observed:
            problems.append(f"observed is missing {key}")
    if not isinstance(observed.get("signals", []), list):
        problems.append("observed.signals must be a list")
    if not isinstance(observed.get("entries", 0), int) or isinstance(observed.get("entries"), bool) \
            or observed.get("entries", 0) < 0:
        problems.append("observed.entries must be a non-negative integer")

    if not payload["remedy"]:
        problems.append("remedy must say what would make this pass")

    verdict = payload["verdict"]
    if layer == PERSISTENCE:
        if verdict not in PERSISTENCE_VERDICTS:
            problems.append(f"{verdict!r} is not a persistence verdict")
        if verdict in FORBIDDEN_PERSISTENCE_VERDICTS:
            problems.append("a persistence verdict may not be a clean result")
        if payload["basis"] not in BASES:
            problems.append("a persistence payload needs a collection basis")
        if payload["attestation_state"] not in ATTESTATION_STATES:
            problems.append("a persistence payload needs an attestation state")
        if payload["cap_grade"] not in GRADES:
            problems.append("a persistence payload needs a cap grade")
        if payload["denial_codes"]:
            problems.append("a persistence payload carries no denial codes")
        if not subject["mechanism"]:
            problems.append("a persistence payload must name its mechanism")
    else:
        if verdict not in POLICY_VERDICTS:
            problems.append(f"{verdict!r} is not a policy verdict")
        if payload["basis"] is not None or payload["cap_grade"] is not None:
            problems.append("a policy answer is an authorisation result, not an evidence claim")
        if subject["resource"] is not None:
            problems.append(
                "a policy payload may not echo the resource: that is how a refusal becomes a "
                "probe about what exists")
        for code in payload["denial_codes"]:
            if code not in DENIAL_CODES:
                problems.append(f"denial code {code!r} is outside the public vocabulary")
        if verdict != "refused" and payload["denial_codes"]:
            problems.append("only a refusal carries a denial code")

    return problems


def assert_valid(payload: dict) -> dict:
    problems = validate(payload)
    if problems:
        raise ContractError("; ".join(problems))
    return payload


# --- adapters (this module is the adapter side, never the decision) -------------------

_ROW_TO_VERDICT = {
    "detected": "detected",
    "benign": "benign",
    "unknown_not_observable": "unknown_not_observable",
    "not_observed": "not_observed",
}


def from_persistence_row(row: dict, *, basis: str, attestation_state: str) -> dict:
    """One matrix row, as a wire payload."""
    return assert_valid(Verdict(
        layer=PERSISTENCE,
        verdict=_ROW_TO_VERDICT[row["result"]],
        remedy=row["control"],
        statement=row["statement"],
        mechanism=row["mechanism"],
        basis=basis,
        attestation_state=attestation_state,
        signals=tuple(row.get("signals", ())),
        entries=int(row.get("entries", 0)),
        cap_grade=row.get("grade") or F.UNKNOWN,
    ).to_wire())


def from_persistence_result(result: dict) -> list[dict]:
    """A whole assessment, row by row. Nothing about the snapshot is summarised away."""
    return [from_persistence_row(row, basis=result["basis"],
                                 attestation_state=result["attestation_state"])
            for row in result["matrix"]]


def from_policy_answer(answer: dict) -> dict:
    """An authorisation answer, with the resource deliberately omitted."""
    refused = not answer.get("allowed")
    verdict = "refused" if refused else "allow"
    if answer.get("verdict") in POLICY_VERDICTS:
        verdict = answer["verdict"]
    return assert_valid(Verdict(
        layer=POLICY,
        verdict=verdict,
        remedy=answer.get("remedy") or "no action available; the request was refused",
        statement=answer.get("denial") or ("allowed" if not refused else "refused"),
        denial_codes=(DENIAL_CODES[0],) if refused else (),
    ).to_wire())


# --- single owner --------------------------------------------------------------------

# Assembled rather than written literally: this module is itself scanned by the check, and a
# literal token would make the checker fail on its own source.
_FORBIDDEN_IN_ENGINE = ("sub" + "process", "sock" + "et", "os." + "system", "po" + "pen")
_FORBIDDEN_IN_ADAPTERS = ("sub" + "process", "sock" + "et", "os." + "system")


def assert_single_owner(reader=None) -> None:
    """The decision is one language, one owner, and nothing on that path shells out.

    Adapters may be polyglot; the verdict engine may not delegate its decision to another
    runtime, because that is how a trust boundary gets spread across memory models.
    """
    import importlib
    import inspect
    import sys

    for name in ENGINE_MODULES + ADAPTER_MODULES:
        if name not in sys.modules:
            importlib.import_module(name)
    modules = {name: sys.modules[name] for name in ENGINE_MODULES + ADAPTER_MODULES}

    for name, module in modules.items():
        source = inspect.getsource(module)
        forbidden = _FORBIDDEN_IN_ENGINE if name in ENGINE_MODULES else _FORBIDDEN_IN_ADAPTERS
        for token in forbidden:
            if token in source:
                raise ContractError(f"{name} may not use {token!r}: the decision must stay "
                                    f"in-process and single-language")

    engine = modules.get("qvault.netpolicy")
    if engine is not None:
        source = inspect.getsource(engine)
        for adapter in ("persistence", "probe", "contract"):
            if f"from . import {adapter}" in source or f"import qvault.{adapter}" in source:
                raise ContractError(f"the policy engine must not depend on the {adapter} "
                                    f"layer; dependencies point inward")

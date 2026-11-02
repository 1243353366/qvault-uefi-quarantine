"""
qvault.threatintel
==================

Threat intelligence and disruption *analysis*. Not collection, not response.

Three questions, deliberately separate:

* what software is operating (the malware evidence graph - existing QVault modules),
* what infrastructure it depends on (this module),
* how the operation finances itself (this module, financial edges).

They stay separate because the evidence for each is of a different kind and a different strength. A
wallet that appears in a sample and in a Telegram advertisement supports "these are related artefacts".
It does not support "this person operates that device", and nothing here will ever say so.

What this module will not do
----------------------------
The doctrine is enforced, not documented:

* **No active collection.** `add` refuses an observation whose source is a probe, a forced rotation, a
  credential use, a purchase, or any wallet interaction. There is no network code in this module at
  all, so "passive by default" is a property of what was built rather than a promise.
* **No attribution verdict.** Claim ceilings are per-claim and enforced: operator attribution from
  passive data cannot exceed HYPOTHESIS, however many observations point the same way.
* **No independence laundering.** Four observations derived from one report are one observation. The
  grade is computed from the number of independent roots, not the number of rows.
* **No retaliation.** `disruption_plan` emits report/notify/preserve/submit actions to named external
  channels. Anything that would act *against* a system - block, flood, rotate, take down - is refused.

Honest limits: this module contains no blockchain client, no exchange data and no live feeds. It is a
reasoning and packaging layer over evidence someone else lawfully obtained. Its outputs are graded
hypotheses plus a package that can be filed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable

GRADES = ("CONFIRMED", "CORROBORATED", "INFERRED", "HYPOTHESIS", "UNKNOWN")
_RANK = {g: i for i, g in enumerate(GRADES)}  # lower index = stronger

#: Sources that are lawful and passive. Anything else is refused: this module does not collect.
PASSIVE_SOURCES = frozenset({
    "passive_observation",       # traffic or artefacts already present on a system you control
    "published_report",          # vendor or CERT write-up
    "provider_disclosure",       # hosting, registrar, exchange, with a lawful basis
    "court_record",              # filed documents
    "blockchain_record",         # public ledger, read only
    "partner_share",             # another team's finding, with its provenance
})

#: Refused on sight. Each would make the analyst a participant rather than an observer.
FORBIDDEN_SOURCES = frozenset({
    "active_probe", "forced_rotation", "credential_use", "purchase",
    "wallet_interaction", "intrusion", "deception_against_operator",
})

#: Ceilings, per claim. A claim cannot outrank its ceiling no matter how much evidence accumulates.
CLAIM_CEILINGS = {
    "infrastructure_relationship": "CORROBORATED",   # two artefacts linked
    "distribution_relationship": "CORROBORATED",
    "financial_relationship": "CORROBORATED",
    "malware_family_correlation": "CORROBORATED",
    "campaign_membership": "INFERRED",               # co-occurrence is weaker than a shared artefact
    "wallet_ownership": "HYPOTHESIS",                # never established passively
    "operator_attribution": "HYPOTHESIS",            # never established passively
    "proxy_operator_attribution": "HYPOTHESIS",      # rotation reveals infrastructure, not people
}

ENTITY_KINDS = frozenset({
    "domain", "ip", "certificate", "sample_hash", "wallet", "smart_contract",
    "telegram_channel", "tor_service", "hosting_provider", "exchange", "proxy_service",
})

#: Lawful disruption, by artefact kind. The verb is always report/notify/preserve/submit.
REPORT_CHANNELS = {
    "domain": ("registrar or hosting provider abuse desk", "report"),
    "ip": ("hosting provider abuse desk or CERT", "report"),
    "certificate": ("certificate authority revocation desk", "report"),
    "sample_hash": ("malware research community and AV vendors", "submit"),
    "wallet": ("exchange compliance and investigators", "submit"),
    "smart_contract": ("chain-analytics provider and investigators", "report"),
    "telegram_channel": ("Telegram abuse reporting", "report"),
    "tor_service": ("preserve evidence, then report to law enforcement", "preserve"),
    "hosting_provider": ("provider abuse desk", "notify"),
    "exchange": ("exchange compliance team", "submit"),
    "proxy_service": ("provider abuse desk", "report"),
}

_ALLOWED_ACTIONS = frozenset({"report", "notify", "preserve", "submit"})


class IntelligenceError(RuntimeError):
    """Bad input: unknown kind, unknown claim, missing provenance."""


class DoctrineViolation(IntelligenceError):
    """An observation or action this project will not perform. Not a bug: a refusal."""


@dataclass(frozen=True)
class Observation:
    """One graded artefact. `derived_from` is what stops four rows masquerading as four sources."""

    claim: str
    subject: str
    source: str
    grade: str
    entities: tuple[str, ...] = ()
    derived_from: tuple[str, ...] = ()
    note: str = ""

    @property
    def id(self) -> str:
        """Identity covers every field, derivation included.

        An earlier version hashed only claim/subject/source/note, so a derived observation inherited
        its parent's id, overwrote it in the case, and made the provenance walk follow itself. A test
        that built a two-step derivation hung rather than failing, which is how it was found.
        """
        raw = json.dumps([self.claim, self.subject, self.source, self.grade, self.note,
                          list(self.entities), list(self.derived_from)], sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Assessor:
    """Collects observations, computes what they actually support, and refuses the rest."""

    def __init__(self) -> None:
        self._obs: dict[str, Observation] = {}

    # ---------- intake ----------

    def add(self, obs: Observation) -> str:
        if obs.source in FORBIDDEN_SOURCES:
            raise DoctrineViolation(f"source {obs.source!r} is collection, not observation")
        if obs.source not in PASSIVE_SOURCES:
            raise IntelligenceError(f"unknown source {obs.source!r}: no silent default")
        if obs.claim not in CLAIM_CEILINGS:
            raise IntelligenceError(f"unknown claim {obs.claim!r}")
        if obs.grade not in GRADES:
            raise IntelligenceError(f"unknown grade {obs.grade!r}")
        for entity in obs.entities:
            kind = entity.split(":", 1)[0]
            if kind not in ENTITY_KINDS:
                raise IntelligenceError(f"unknown entity kind {kind!r}")
        self._obs[obs.id] = obs
        return obs.id

    # ---------- independence ----------

    def roots(self, obs_id: str) -> set[str]:
        """Independent provenance roots behind one observation, following derivation transitively."""
        seen: set[str] = set()
        visited: set[str] = set()
        stack = [obs_id]
        while stack:
            current = stack.pop()
            if current in visited:
                raise IntelligenceError(f"derivation cycle at observation {current}")
            visited.add(current)
            obs = self._obs.get(current)
            if obs is None:
                raise IntelligenceError(f"observation {current} is not in this case")
            if not obs.derived_from:
                seen.add(f"{obs.source}|{obs.id}")
            else:
                stack.extend(obs.derived_from)
        return seen

    def independence(self, obs_ids: Iterable[str]) -> int:
        roots: set[str] = set()
        for obs_id in obs_ids:
            roots |= self.roots(obs_id)
        return len(roots)

    # ---------- grading ----------

    def grade(self, obs_ids: Iterable[str], claim: str) -> dict:
        """The grade the evidence supports: weakest of claimed, ceiling, and root count."""
        ids = list(obs_ids)
        if not ids:
            raise IntelligenceError("no observations")
        if claim not in CLAIM_CEILINGS:
            raise IntelligenceError(f"unknown claim {claim!r}")
        roots = self.independence(ids)
        rank = min(_RANK[self._obs[i].grade] for i in ids)
        # One root cannot exceed INFERRED, a single source no matter how much it says.
        rank = max(rank, _RANK["INFERRED"]) if roots < 2 else max(rank, _RANK["CORROBORATED"])
        rank = max(rank, _RANK[CLAIM_CEILINGS[claim]])
        grade = GRADES[rank]
        return {
            "claim": claim,
            "grade": grade,
            "observations": len(ids),
            "independent_roots": roots,
            "ceiling": CLAIM_CEILINGS[claim],
            "note": ("one provenance root: more rows do not make it corroborated" if roots < 2
                     else f"{roots} independent roots"),
        }

    def attribution(self) -> list[dict]:
        """Hypotheses, labelled as hypotheses. There is deliberately no identity field."""
        out = []
        for claim in ("operator_attribution", "wallet_ownership", "proxy_operator_attribution"):
            ids = [i for i, o in self._obs.items() if o.claim == claim]
            if ids:
                result = self.grade(ids, claim)
                result["never_establishes"] = "who controls the artefact"
                out.append(result)
        return out

    # ---------- graph ----------

    def graph(self) -> dict:
        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        for obs in self._obs.values():
            ents = list(obs.entities)
            for entity in ents:
                nodes.setdefault(entity, {"id": entity, "kind": entity.split(":", 1)[0],
                                          "claims": []})
                nodes[entity]["claims"].append(obs.claim)
            for a, b in zip(ents, ents[1:]):
                edges.append({"from": a, "to": b, "claim": obs.claim, "grade": obs.grade,
                              "source": obs.source, "observation": obs.id})
        return {"nodes": sorted(nodes.values(), key=lambda n: n["id"]), "edges": edges}


def deleted_domains_are_not_enough(observations: Iterable[Observation]) -> dict:
    """Blockchain pointers: the rediscovery problem, stated as a property rather than a worry.

    If a sample fetches its infrastructure pointer from a public ledger, taking down the domains
    removes the current C2 and leaves the lookup intact. The operation rotates and the blocklist is
    stale. This function reports that dependency so a defender does not mistake a takedown for a fix.
    """
    pointers = [o for o in observations if o.claim == "campaign_membership"
                and any(e.startswith("smart_contract:") for e in o.entities)]
    if not pointers:
        return {"blockchain_dependent": False, "grade": "UNKNOWN",
                "note": "no ledger pointer observed; absence of evidence, not evidence of absence"}
    return {
        "blockchain_dependent": True,
        "grade": "INFERRED",
        "pointers": [o.subject for o in pointers],
        "domains_sufficient": False,
        "note": "domain blocking removes current C2, not the rediscovery path; monitor the ledger",
    }


def disruption_plan(entity_keys: Iterable[str]) -> list[dict]:
    """Lawful avenues only. Refuses anything that acts against a third-party system."""
    plan = []
    for entity in entity_keys:
        kind = entity.split(":", 1)[0]
        channel, action = REPORT_CHANNELS.get(kind, ("no lawful avenue recorded", "preserve"))
        if action not in _ALLOWED_ACTIONS:
            raise DoctrineViolation(f"action {action!r} is not a report/notify/preserve/submit")
        plan.append({"entity": entity, "action": action, "channel": channel})
    return plan


def evidence_package(assessor: Assessor, *, case: str, artifacts: dict[str, bytes],
                     alternatives: dict[str, str]) -> dict:
    """A package that can be filed: hashed artefacts, grades, independence, and the alternative read.

    `alternatives` is required per claim. An intelligence product without a competing explanation is
    an accusation with a graph attached.
    """
    for claim in ("operator_attribution", "wallet_ownership", "infrastructure_relationship"):
        if claim in alternatives and not alternatives[claim].strip():
            raise IntelligenceError(f"alternative explanation for {claim} is empty")
    hypotheses = assessor.attribution()
    for hyp in hypotheses:
        if hyp["claim"] not in alternatives:
            raise IntelligenceError(f"no alternative explanation offered for {hyp['claim']}")
    return {
        "case": case,
        "artifacts": [{"name": n, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}
                      for n, b in sorted(artifacts.items())],
        "graph": assessor.graph(),
        "hypotheses": hypotheses,
        "alternatives": dict(alternatives),
        "does_not_establish": [
            "who controls a wallet, domain, or account",
            "that related artefacts share an operator",
            "that a device in the evidence belongs to any identified person",
        ],
    }

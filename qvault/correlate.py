"""
qvault.correlate
================

A temporal evidence graph, and the rule that keeps it honest.

Why this exists
---------------
An unpublished implant matches no indicator. What it cannot avoid is *interacting*:
it must be installed, executed, persist, touch something sensitive, and communicate.
Any single one of those interactions has an innocent explanation. Two independent
ones, close in time, on the same subject, are harder to explain innocently. That is
the only reason correlation works, and it is also why most correlation engines
overstate themselves.

The rule
--------
**Temporal proximity alone never raises a grade.**

Two events in the same minute are not corroboration if they came from the same
artifact class or the same evidence plane: one log file mentioning two things twice is
still one log file. Corroboration requires *independence*, which here means different
event kinds drawn from different evidence planes. A cluster of four events from one
plane is not four times the evidence; it is one plane, four times.

Consequences that follow from it:

* a cluster confined to one plane is capped at `INFERRED`, however many events it
  contains;
* grade is raised only when at least three distinct kinds cross at least two planes;
* every cluster reports the benign explanations that were offered, and says so when
  none were, rather than implying that none exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import findings as F

# Event kinds. Deliberately coarse: this is a triage vocabulary, not a taxonomy.
INSTALL = "install"
EXECUTION = "execution"
PERSISTENCE = "persistence"
CONTACT = "contact"
PERMISSION = "permission"
DOWNLOAD = "download"

KINDS = (INSTALL, EXECUTION, PERSISTENCE, CONTACT, PERMISSION, DOWNLOAD)

# Pairs whose co-occurrence is worth joining even across different subjects: an
# install followed by an execution is a sequence, not a coincidence.
COMPLEMENTARY = frozenset({
    (INSTALL, EXECUTION), (EXECUTION, CONTACT), (PERSISTENCE, EXECUTION),
    (DOWNLOAD, EXECUTION), (PERMISSION, CONTACT), (INSTALL, PERSISTENCE),
})

_RANK = {F.UNKNOWN: 0, F.HYPOTHESIS: 1, F.INFERRED: 2, F.CORROBORATED: 3, F.CONFIRMED: 4}
_GRADE = {v: k for k, v in _RANK.items()}


class CorrelationError(ValueError):
    """Raised when a cluster would overstate its own independence."""


@dataclass(frozen=True)
class Event:
    """One observed interaction, already graded."""

    ts: int              # epoch seconds; correlation is temporal, not causal
    subject: str         # bundle id, process name, file path, host name
    kind: str
    plane: str
    grade: str
    source: str = ""
    benign: str = ""     # upstream's usual_reason, when it offered one

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise CorrelationError(f"unknown event kind {self.kind!r}; known: {KINDS}")
        if self.grade not in F.GRADES:
            raise CorrelationError(f"unknown grade {self.grade!r}")
        if not self.subject.strip():
            raise CorrelationError("an event needs a subject")

    @property
    def normalised_subject(self) -> str:
        return self.subject.strip().lower()


def _complementary(a: str, b: str) -> bool:
    return (a, b) in COMPLEMENTARY or (b, a) in COMPLEMENTARY


def _linked(a: Event, b: Event, window_s: int) -> bool:
    """Whether two events belong in one cluster."""
    if a.normalised_subject == b.normalised_subject:
        return True
    if abs(a.ts - b.ts) > window_s:
        return False
    # Different subjects, close in time: join only for a plausible sequence, and
    # never for two events of the same kind (that is repetition, not sequence).
    return a.kind != b.kind and _complementary(a.kind, b.kind)


def build_clusters(events, window_s: int = 300) -> list[list[Event]]:
    """Union-find over the link relation. Order-independent by construction."""
    events = list(events)
    parent = list(range(len(events)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    for i in range(len(events)):
        for j in range(i + 1, len(events)):
            if _linked(events[i], events[j], window_s):
                union(i, j)

    groups: dict[int, list[Event]] = {}
    for idx, ev in enumerate(events):
        groups.setdefault(find(idx), []).append(ev)
    clusters = [sorted(g, key=lambda e: e.ts) for g in groups.values()]
    # Deterministic output: insertion order of the union-find roots leaked the input
    # order into the result, so the same evidence produced different reports.
    clusters.sort(key=lambda c: (c[0].ts, c[0].normalised_subject))
    return clusters


def assess_cluster(cluster) -> dict:
    """Grade a cluster from its independence, not its size."""
    cluster = sorted(cluster, key=lambda e: e.ts)
    if not cluster:
        raise CorrelationError("empty cluster")

    kinds = {e.kind for e in cluster}
    planes = {e.plane for e in cluster}
    subjects = {e.subject for e in cluster}
    base_rank = max(_RANK[e.grade] for e in cluster)

    raised = base_rank
    if len(kinds) >= 3 and len(planes) >= 2:
        raised = min(_RANK[F.CONFIRMED], base_rank + 1)

    # One plane is one source of truth, however many events it contributes.
    capped = len(planes) == 1
    if capped:
        raised = min(raised, _RANK[F.INFERRED])

    grade = _GRADE[raised]
    if len(planes) >= 2 and raised >= _RANK[F.CORROBORATED]:
        status = "correlated"
    elif raised >= _RANK[F.HYPOTHESIS]:
        status = "suspicious"
    else:
        status = "observation"

    benign = [e.benign for e in cluster if e.benign]
    return {
        "subjects": sorted(subjects),
        "events": len(cluster),
        "kinds": sorted(kinds),
        "planes": sorted(planes),
        "span_s": cluster[-1].ts - cluster[0].ts,
        "base_grade": _GRADE[base_rank],
        "grade": grade,
        "status": status,
        "raised": raised > base_rank,
        "capped_by_single_plane": capped,
        "benign_candidates": benign,
        "unresolved_gaps": [] if benign else [
            "no benign explanation recorded for this cluster: absence of a proposed "
            "explanation is not evidence that none exists"
        ],
    }


def assess(events, window_s: int = 300) -> dict:
    """Cluster and grade a whole set of events."""
    clusters = build_clusters(events, window_s=window_s)
    assessed = [assess_cluster(c) for c in clusters]
    assessed.sort(key=lambda c: (-_RANK[c["grade"]], -c["events"]))
    return {
        "clusters": assessed,
        "event_count": sum(len(c) for c in clusters),
        "correlated": [c for c in assessed if c["status"] == "correlated"],
        "statement": (
            f"{len(assessed)} cluster(s) from {sum(len(c) for c in clusters)} event(s); "
            f"{sum(1 for c in assessed if c['status'] == 'correlated')} reach correlated "
            "status, which still means 'worth a look', not 'compromised'."
        ),
    }

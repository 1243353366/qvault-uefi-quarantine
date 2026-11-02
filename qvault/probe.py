"""A probe that can only answer "what did I observe", never "what is hidden".

The contract this module implements:

- **Passive.** It reads a policy decision that already exists. It does not mutate policy
  state, touch the filesystem, open a connection, or ask a target host anything.
- **Coarse.** Two surfaces only: a single token per request, or the state of the caller's
  own gates. Neither names a resource the caller did not supply.
- **Bounded and single-shot.** One attempt, no retries, no recursion, no discovery loop.
  Exceeding the budget fails closed to `UNKNOWN`.
- **Fail closed.** An error, an unreadable input, or a slow answer becomes `UNKNOWN`.
  "I could not observe" never becomes "it is absent".
- **Non-oracular.** `ask()` returns the same token for a forbidden resource and one that
  does not exist, and performs the same work for both.

The distinction that keeps this honest: `context()` reports on the caller's *own* policy
position, where the labels are things they already know (which gates their context closes).
`ask()` reports on a resource, so it returns one token and nothing else.
"""

import time
from dataclasses import dataclass

from . import netpolicy as N

ALLOW = "ALLOW"
DENY = "DENY"
UNKNOWN = "UNKNOWN"
PARTIAL = "PARTIAL"
UNATTESTED = "UNATTESTED"

#: The complete vocabulary. Anything else would be a leak by construction.
TOKENS = (ALLOW, DENY, UNKNOWN, PARTIAL, UNATTESTED)


@dataclass(frozen=True)
class Budget:
    """Hard limits. There is no configuration for "try again"."""

    max_seconds: float = 0.05
    max_calls: int = 1


class Probe:
    """A read-only view of one policy decision."""

    __slots__ = ("_decision", "_budget", "_clock", "_calls")

    def __init__(self, decision: "N.Decision", *, budget: Budget | None = None,
                 clock=time.monotonic) -> None:
        self._decision = decision
        self._budget = budget or Budget()
        self._clock = clock
        self._calls = 0

    @property
    def calls(self) -> int:
        return self._calls

    def ask(self, resource) -> str:
        """One token about one resource. Identical for forbidden and nonexistent."""
        if self._calls >= self._budget.max_calls:
            return UNKNOWN                      # exhausted, not retried
        self._calls += 1
        started = self._clock()
        if not isinstance(resource, str) or not resource:
            return DENY                         # unknown input: generic refusal
        try:
            verdict = N._evaluate(self._decision, resource)
        except Exception:                       # noqa: BLE001 - any failure is UNKNOWN
            return UNKNOWN
        if self._clock() - started > self._budget.max_seconds:
            return UNKNOWN                      # too slow to be trusted as bounded
        return ALLOW if verdict.allowed else DENY

    def context(self, *, attested: bool | None = None, shares: int | None = None,
                days: int | None = None, collection: str | None = None) -> dict:
        """The caller's own gates, by label. No resource identity, no hidden counts."""
        gates: dict[str, str] = {}
        for gate in N.RESOURCES:
            kwargs = self._gate_kwargs(gate, attested=attested, shares=shares, days=days,
                                       collection=collection)
            if kwargs is None:
                gates[gate] = UNKNOWN
                continue
            verdict = N._evaluate_one(self._decision, gate, **kwargs)
            gates[gate] = ALLOW if verdict.allowed else DENY
        return {"verdict": self._combine(gates, attested), "gates": gates}

    def _gate_kwargs(self, gate, *, attested, shares, days, collection):
        if gate in ("egress", "write"):
            return {}
        if gate == "collection":
            return {"requested": collection} if collection is not None else None
        if gate == "retention":
            return {"requested": days} if days is not None else None
        if gate == "custody":
            return {"shares": shares} if shares is not None else None
        if gate == "attestation":
            if attested is not None:
                return {"attested": attested}
            if not self._decision.settings["require_attestation"]:
                return {}
            return None
        return None

    def _combine(self, gates: dict, attested) -> str:
        # Missing attestation outranks a denial: nothing can be concluded from an
        # evidence class that was never established, so the honest answer is that the
        # question is unanswerable rather than that the answer is no.
        if gates.get("attestation") == UNKNOWN and self._decision.settings["require_attestation"]:
            return UNATTESTED
        if any(token == DENY for token in gates.values()):
            return DENY
        if any(token == UNKNOWN for token in gates.values()):
            return PARTIAL
        return ALLOW


def observe(decision: "N.Decision", resource, **kwargs) -> str:
    """Single-shot convenience wrapper. One attempt, no state carried."""
    return Probe(decision).ask(resource)

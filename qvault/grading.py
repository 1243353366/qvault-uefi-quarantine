"""Grade arithmetic, in one place, for layers that must not know each other's ordering.

The persistence layer needs to say "two signals from an offline image is INFERRED, and no
better". It should not need to know how `separation` orders grades, and it must not reach
into a private rank table to find out. This module is the public seam: give it a basis, a
signal count and an attestation state, and it returns a grade that cannot exceed what the
collection method supports.
"""

from . import findings as F
from . import separation as S


class GradingError(ValueError):
    """Raised when a basis or attestation state is not one we can reason about."""


#: What each collection basis is worth, as evidence classes. Reading a host through itself
#: is a self-report, so it supports no graded finding at all.
BASIS_CLASSES: dict[str, tuple[str, ...]] = {
    "synthetic": (S.SELF_REPORT,),
    "live_host": (S.SELF_REPORT,),
    "offline_image": (S.INDEPENDENT_MEASUREMENT,),
    "attested_image": (S.INDEPENDENT_MEASUREMENT, S.HARDWARE_ANCHOR),
}

#: Bases that only count as themselves when the attestation actually verified. An
#: "attested" image whose attestation is absent is an offline image, not a promise.
REQUIRES_ATTESTATION = frozenset({"attested_image"})

ATTESTATION_STATES = ("verified", "absent", "unknown")

#: What a number of independent-looking signals proposes, before any ceiling applies.
#: One signal is a hypothesis; several agreeing signals are still one snapshot.
SIGNAL_GRADES = ((0, F.UNKNOWN), (1, F.HYPOTHESIS), (2, F.INFERRED))


def _validate(basis: str, attestation_state: str) -> None:
    if basis not in BASIS_CLASSES:
        raise GradingError(f"unknown basis {basis!r}; known: {sorted(BASIS_CLASSES)}")
    if attestation_state not in ATTESTATION_STATES:
        raise GradingError(
            f"unknown attestation state {attestation_state!r}; known: {ATTESTATION_STATES}")


def proposed_grade(signal_count: int) -> str:
    """What the signals alone propose, ignoring how they were collected."""
    if not isinstance(signal_count, int) or isinstance(signal_count, bool) or signal_count < 0:
        raise GradingError(f"signal_count must be a non-negative integer, got {signal_count!r}")
    for threshold, grade in SIGNAL_GRADES:
        if signal_count <= threshold:
            return grade
    return SIGNAL_GRADES[-1][1]


def effective_classes(basis: str, attestation_state: str = "absent") -> tuple[str, ...]:
    """The evidence classes this basis actually delivers, attestation included."""
    _validate(basis, attestation_state)
    classes = BASIS_CLASSES[basis]
    if basis in REQUIRES_ATTESTATION and attestation_state != "verified":
        without_hardware = tuple(c for c in classes if c != S.HARDWARE_ANCHOR)
        return without_hardware or (S.SELF_REPORT,)
    return classes


def ceiling(basis: str, attestation_state: str = "absent") -> str | None:
    """The strongest grade this basis can support, or None when it supports none."""
    return S.grade_ceiling(effective_classes(basis, attestation_state))


def cap_grade(*, basis: str, signal_count: int, attestation_state: str = "absent") -> str:
    """The grade to report. Public, and the only way this layer grades anything.

    A ceiling is a limit, not a target: a strong basis never lifts a weak signal count.
    """
    proposed = proposed_grade(signal_count)
    limit = ceiling(basis, attestation_state)
    return S.cap_grade(proposed, limit)


def explain(*, basis: str, signal_count: int, attestation_state: str = "absent") -> dict:
    """The same answer, with the reasoning attached for a report."""
    proposed = proposed_grade(signal_count)
    limit = ceiling(basis, attestation_state)
    grade = S.cap_grade(proposed, limit)
    if limit is None:
        reason = (f"a {basis} read is a self-report and cannot support a graded finding")
    elif grade != proposed:
        reason = f"{proposed} proposed by {signal_count} signal(s), capped to {limit} by {basis}"
    else:
        reason = f"{proposed} from {signal_count} signal(s), within the {basis} ceiling {limit}"
    return {"grade": grade, "proposed": proposed, "ceiling": limit, "basis": basis,
            "attestation_state": attestation_state, "signal_count": signal_count,
            "reason": reason}

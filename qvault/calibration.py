"""
qvault.calibration
==================

Measuring false positives and false negatives instead of promising none.

The claim that must not be made
-------------------------------
"No false positives, no false negatives" is not a property a detector can have, and a
tool that prints it is telling you something about its author, not its accuracy. Every
detector has both rates; what varies is whether anyone measured them.

So this module refuses the sentence and does the measurement. Given a labelled corpus of
cases, it reports a confusion matrix, per-class rates with confidence intervals, and the
one number that most matters for a detection tool: the **upper bound on the error rate
given how little we have tested**. Zero errors in 40 cases is not zero; it is "below
about 7 percent, at 95 percent confidence".

Abstention is not accuracy
--------------------------
A detector can drive its error rate to zero by answering "inconclusive" to everything.
That is why abstentions are counted separately and against the claim: an abstention on a
positive case is a missed trojan (operationally a false negative), and an abstention on a
negative case is a needless alarm. Reporting them as "not wrong" would be the cheapest
possible way to look perfect.

The rule of three
-----------------
With zero observed errors in n independent cases, the 95 percent upper bound on the true
error rate is approximately 3/n. That is the honest way to state a clean run: a bound,
not an absence.
"""

from __future__ import annotations

import math

from . import findings as F

#: Verdicts that assert a problem, and verdicts that do not. `inconclusive` is neither.
POSITIVE_VERDICTS = {F.SUSPICIOUS_VERDICT, F.MALICIOUS_VERDICT}
NEGATIVE_VERDICTS = {F.NO_EVIDENCE_FOUND, F.WITHDRAWN_ONLY if hasattr(F, "WITHDRAWN_ONLY")
                     else F.NO_EVIDENCE_FOUND}
ABSTAIN_VERDICTS = {F.INCONCLUSIVE}

TP = "true_positive"
FP = "false_positive"
TN = "true_negative"
FN = "false_negative"
ABSTAINED_POSITIVE = "abstained_positive"
ABSTAINED_NEGATIVE = "abstained_negative"

OUTCOMES = (TP, FP, TN, FN, ABSTAINED_POSITIVE, ABSTAINED_NEGATIVE)

#: Below this many cases in either class, a rate is not reportable at all.
MIN_PER_CLASS = 20


class CalibrationError(ValueError):
    """Raised when an accuracy claim is not supported by the corpus behind it."""


class Bench:
    """A labelled corpus: what each case really is, and what the tool said."""

    def __init__(self, name: str = "unnamed"):
        self.name = name
        self.cases: list[tuple[str, str, str]] = []   # (case_id, expected, produced)

    def add(self, case_id: str, expected: str, produced: str) -> "Bench":
        if expected not in ("malicious", "benign"):
            raise CalibrationError(f"expected must be 'malicious' or 'benign', not {expected!r}")
        known = POSITIVE_VERDICTS | NEGATIVE_VERDICTS | ABSTAIN_VERDICTS
        if produced not in known:
            raise CalibrationError(f"produced verdict {produced!r} is outside the vocabulary")
        self.cases.append((case_id, expected, produced))
        return self

    @property
    def positives(self) -> int:
        return sum(1 for _i, e, _p in self.cases if e == "malicious")

    @property
    def negatives(self) -> int:
        return sum(1 for _i, e, _p in self.cases if e == "benign")


def _classify(expected: str, produced: str) -> str:
    if expected == "malicious":
        if produced in POSITIVE_VERDICTS:
            return TP
        return FN if produced in NEGATIVE_VERDICTS else ABSTAINED_POSITIVE
    if produced in POSITIVE_VERDICTS:
        return FP
    return TN if produced in NEGATIVE_VERDICTS else ABSTAINED_NEGATIVE


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval: behaves at 0/n, where the normal approximation does not."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def zero_error_upper_bound(n: int, confidence: float = 0.95) -> float:
    """Upper bound on a rate given zero observed errors in n cases (rule of three)."""
    if n <= 0:
        return 1.0
    return round(1 - (1 - confidence) ** (1 / n), 4)


def evaluate(bench: Bench) -> dict:
    """Confusion matrix, rates, intervals, and what may honestly be claimed."""
    if not isinstance(bench, Bench):
        raise CalibrationError(
            f"evaluate() takes a Bench, not {type(bench).__name__}. Build one with "
            "Bench().add(case_id, expected, produced) so each case states what the "
            "sample really was; a bare list of verdicts cannot measure false positives "
            "or false negatives, because the truth is missing."
        )
    if not bench.cases:
        raise CalibrationError("no cases: an empty corpus measures nothing")

    counts = {o: 0 for o in OUTCOMES}
    for _case, expected, produced in bench.cases:
        counts[_classify(expected, produced)] += 1

    pos, neg = bench.positives, bench.negatives

    def rate(k: int, n: int) -> float | None:
        return None if n == 0 else round(k / n, 4)

    fn_total = counts[FN] + counts[ABSTAINED_POSITIVE]
    fp_total = counts[FP] + counts[ABSTAINED_NEGATIVE]

    gaps: list[str] = []
    if pos < MIN_PER_CLASS:
        gaps.append(
            f"corpus_too_small_for_recall: {pos} positive case(s), needs {MIN_PER_CLASS}"
        )
    if neg < MIN_PER_CLASS:
        gaps.append(
            f"corpus_too_small_for_specificity: {neg} negative case(s), needs {MIN_PER_CLASS}"
        )
    if counts[ABSTAINED_POSITIVE] or counts[ABSTAINED_NEGATIVE]:
        gaps.append(
            f"abstentions:{counts[ABSTAINED_POSITIVE] + counts[ABSTAINED_NEGATIVE]}: "
            "inconclusive answers are counted against accuracy, not excluded from it"
        )

    measurable = pos >= MIN_PER_CLASS and neg >= MIN_PER_CLASS

    return {
        "bench": bench.name,
        "cases": len(bench.cases),
        "counts": counts,
        "recall": rate(counts[TP], pos),
        "false_negative_rate": rate(fn_total, pos),
        "specificity": rate(counts[TN], neg),
        "false_positive_rate": rate(fp_total, neg),
        "precision": rate(counts[TP], counts[TP] + counts[FP]),
        "false_negative_ci": wilson(fn_total, pos) if pos else (0.0, 1.0),
        "false_positive_ci": wilson(fp_total, neg) if neg else (0.0, 1.0),
        "zero_error_bound": (
            f"with 0 errors in {pos} positives, the false-negative rate is at most "
            f"{zero_error_upper_bound(pos):.1%} (95% confidence)" if counts[FN] == 0 and pos else ""
        ),
        "measurable": measurable,
        "gaps": gaps,
        "zero_claim_allowed": False,
        "statement": _statement(counts, pos, neg, measurable, bench.name),
    }


def _statement(counts: dict, pos: int, neg: int, measurable: bool, name: str) -> str:
    if not measurable:
        return (
            f"{name}: {len(str(counts))} outcome classes over {pos} malicious and {neg} "
            "benign cases. Below the minimum corpus per class, no rate is reported, "
            "because a rate from a handful of cases is a guess with a decimal point."
        )
    fn = counts[FN] + counts[ABSTAINED_POSITIVE]
    fp = counts[FP] + counts[ABSTAINED_NEGATIVE]
    return (
        f"{name}: of {pos} malicious cases {pos - fn} were flagged ({fn} missed, "
        f"{counts[ABSTAINED_POSITIVE]} of them as inconclusive); of {neg} benign cases "
        f"{neg - fp} were left alone ({fp} flagged, {counts[ABSTAINED_NEGATIVE]} as "
        "inconclusive). These are the measured rates for this corpus. They are not a "
        "guarantee about the next sample."
    )


def refuse_zero_claim(text: str) -> None:
    """Reject the sentence no detector can support."""
    lowered = text.lower()
    for phrase in ("no false positives", "no false negatives", "zero false positives",
                   "zero false negatives", "cannot be fooled", "100% accurate"):
        if phrase in lowered:
            raise CalibrationError(
                f"claim {phrase!r} is unmeasurable: a detector has error rates, and the "
                "only honest form is a bound from a labelled corpus"
            )


def compare(a: dict, b: dict) -> dict:
    """Whether one run measured better, with the overlap check that usually says 'no'."""
    if not (a["measurable"] and b["measurable"]):
        return {"comparable": False,
                "why": "at least one run is below the minimum corpus per class"}
    fa, fb = a["false_negative_rate"], b["false_negative_rate"]
    overlap = not (a["false_negative_ci"][1] < b["false_negative_ci"][0]
                   or b["false_negative_ci"][1] < a["false_negative_ci"][0])
    return {
        "comparable": True,
        "delta_fn": round((fa or 0) - (fb or 0), 4),
        "intervals_overlap": overlap,
        "claim": ("indistinguishable on this corpus" if overlap else
                  "a real difference on this corpus only, not necessarily on another"),
    }

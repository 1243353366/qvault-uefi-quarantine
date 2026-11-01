# Merging Zero-Breach-Toolkit into qvault

Upstream: https://github.com/interplains/Zero-Breach-Toolkit by
[@interplains](https://github.com/interplains) (Apache-2.0).
Release consumed: **v2.0.2**, commit `90148ea` (signed). The vendored tree is
byte-identical to that tag (`git diff v2.0.2 5c86adf -- scan/zbtriage` is empty) and is
pinned by digest in `vendor/UPSTREAM.sha256`, which a test verifies.

Credit: the detection engine, its evidence taxonomy and its doctrine are theirs. This
repository's contribution is what surrounds them.

## The strategy question, answered

The choice offered was *fork and contribute* versus *independent successor using it as
a research reference*. This is neither exactly: it is a **vendored upstream behind an
adapter**, which is the only option that survives contact with both codebases.

A fork would mean maintaining ~28k lines of fast-moving upstream while also enforcing
local rules. Those two obligations pull in opposite directions, and the failure is
silent: upstream adds an evidence grade, the local mapping has never heard of it, and
the new artefact class is graded by a default nobody chose. An independent successor
would throw away a working detector and re-earn every bug it has already fixed.

So the split is by responsibility:

| Concern | Owner |
|---|---|
| Which artifacts to read, which indicator matched, which artifact class | upstream (`vendor/zbtriage`, unmodified) |
| What a match is worth as evidence, how gaps downgrade it, whether it may carry an attribution | qvault (`qvault/zbt_bridge.py`) |

Nothing in `vendor/` is edited. Attribution is preserved in `vendor/LICENSE` and
`vendor/NOTICE`.

## What the merge actually adds

**1. Grading at the seam.** Upstream's `EV_*` grade describes the *artifact*: `on-disk`
means a file fingerprint matched. It does not say what that is worth against an
adversary who can lie about the filesystem. `zbt_bridge` maps each class to an evidence
plane and a grade from this project's scale, so a hit inherits both the detector's
finding and the analyst's caution.

The honest result: every upstream grade maps to the historical plane, and the
historical plane is forgeable by the subject. `adversarial_value(EV_ON_DISK)` returns
`none`. That is not a criticism of the detector; it is the correct reading of evidence
read through the operating system under suspicion.

**2. Vocabulary pinning.** `assert_vocabulary()` fails if upstream's `EVIDENCE_ORDER`
and the local map diverge, so a new artifact class cannot be silently treated as benign.

**3. Rules that bind their output.** Hits become `Observation`s, never `Finding`s.
Promotion requires a named benign explanation (F2), and an unexcluded one caps the
result at `suspicious`. `run_verdict()` maps `CLEAN/HITS/PARTIAL/UNKNOWN` onto this
project's vocabulary, which has no `clean` value, and preserves upstream's mandatory
D1 line verbatim.

**4. Attribution gating.** Upstream carries `family` and `source` per hit. A single
feed cannot support a family name however confident it reads, so `attribution_refusal()`
returns a refusal unless two independently validated upstreams stand behind it (A4).

**5. The correlation engine.** `qvault/correlate.py` is the bridge from known-indicator
matching toward unknown-threat detection: interactions are graph nodes, and grade comes
from independence rather than count. Four contacts from one plane stay `INFERRED`;
install plus execution plus contact across three planes reaches `correlated`.

## What was deliberately not merged

The CLI, GUI, build system, packaged binaries, locales and the IOC corpus itself. The
IOC corpus is upstream's currency and it moves weekly; embedding a snapshot would
reproduce exactly the staleness problem A4 describes. qvault consumes detections, not
the feed.

## Known gaps in the merged system

1. **No enforcement of the isolation model across the process boundary.** `isolation.py`
   states where the readers and parsers must run; nothing verifies the substrate
   honours it.
2. **Upstream's own test suite is not vendored**, so upstream regressions surface only
   on refresh, not in this repo's CI.
3. **The correlation window is a constant** (300 s). Real intrusion sequences span
   hours; the window is a starting point, not a measurement.
4. **Vendoring pins a snapshot**, so upstream fixes arrive only on manual refresh. The
   refresh procedure is in `vendor/UPSTREAM.md`.

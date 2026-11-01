# Architectural limitations

Four limitations stated as architectural rather than incidental. Each has a
proposed control, and each control buys something specific while leaving a
residual. Modelling them is `qvault/limitations.py`; this document is the argument.

---

## The evidence-plane table

Every claim a detection system makes rests on some source of evidence. Those
sources differ in one property that matters more than the rest: whether the thing
under suspicion can influence them.

| Plane | Establishes | Subject can forge it | Needs physical access |
|---|---|---|---|
| Live state | process existed, file content | **yes** | no |
| Historical record | past activity, file content, network contact | **yes** | no |
| Wire observation | network contact | no | no |
| Firmware read via OS | firmware integrity | **yes** | no |
| Firmware read out-of-band | firmware integrity | no | **yes** |
| Threat intelligence | object is malicious | **yes** (via source) | no |
| Behavioural baseline | behaviour is normal | **yes** (see below) | no |

A proposition is supported only by planes that actually establish it, and against a
capable adversary only by planes the subject cannot forge. `establish()` computes
that instead of asserting it.

---

## A1. Limited live-state visibility

**Consequence.** Historical records can miss an active compromise.

**Control.** Optional live-response acquisition.

**What it buys.** Current state that logging never captured: running processes,
open connections, memory-resident code, the things that by definition do not
survive to disk.

**What it cannot buy.** Integrity. Live state is read through the subject's own
kernel. If the implant is inside that kernel, it answers the questions. On a host
running any of the three families in this report, live response is an interview
with a witness who may be the suspect.

**Residual.** Live acquisition also mutates the subject: timestamps change,
connections are made, memory pages are touched. It degrades the history it was
meant to supplement, and the degradation is not recoverable.

**How to use it.** For breadth, never for integrity claims. Pair every live
finding with an out-of-band observation before it enters a report as fact.

---

## A2. Firmware blind spots

**Consequence.** OS-level scans cannot establish firmware integrity.

**Control.** Independent firmware acquisition.

**What it buys.** The only evidence in this list that does not route through the
subject.

**What it cannot buy.** Coverage without physical access, and not proof that what
you read equals what the chip holds. In-circuit read-back equivalence is an open
question (HARDWARE_TEST_QUESTIONS.md H8) and may differ from a chip-off read in ways
that matter legally.

**Residual.** This is the sharpest limitation in the set, because the control has a
qualifier that is easy to lose. **"Independent" means the acquisition path does not
pass through the subject.** A flash read performed by a driver inside a possibly
compromised OS is `firmware_via_os`: the implant answers the read, and a clean
result means only that the implant is a competent liar. Independent acquisition
needs a programmer, a clip or a chip-off, which needs hands on hardware. Most
fleets do not have that, so in practice the common case is a scan that cannot
answer the question it appears to answer.

**How to use it.** Label the path in every report. A firmware hash obtained through
the OS is a claim about the OS, not about the flash.

---

## A3. Baseline limitations

**Consequence.** Legitimate unusual behaviour can look suspicious.

**Control.** Per-device behavioural baselines.

**What it buys.** Fewer false positives from genuinely unusual but legitimate work:
the developer with unusual tooling, the finance machine that runs macros, the lab
host that talks to odd addresses.

**What it cannot buy.** Validity when the baseline was learned after compromise.

**Residual.** Two failure modes, and the second is worse than the first.

If the implant was resident during the learning window, its behaviour *is* the
baseline, and every subsequent deviation is measured from a poisoned origin. The
system then reports the machine as well-behaved precisely because it is infected.
`baseline_validity()` therefore returns `unverified` whenever the compromise window
is unknown, never `valid`: absence of evidence of earlier compromise is not evidence
of a clean baseline.

The second failure is drift. A patient adversary moves slowly enough that the
baseline follows, which turns the control into an accelerant for the threat it was
meant to catch. Long-dwell actors are favoured by baselines, not disadvantaged.

**How to use it.** Baseline only from a known-good rebuild with a recorded
provenance, re-validate after every rebuild, and treat a deviation as a lead rather
than a verdict.

---

## A4. Indicator trust

**Consequence.** Bad or poisoned intelligence can generate bad findings.

**Control.** Source provenance and independent validation.

**What it buys.** Resistance to one feed's error, and a visible chain of custody for
each indicator.

**What it cannot buy.** Independence when feeds resell a single upstream. Three
feeds quoting one vendor is one source, and `intel_trust()` reports that as
`circular` rather than as corroboration.

**Residual.** Note the direction of the attack. Poisoning a feed to cause a false
positive is loud: it produces an alert someone investigates. Poisoning it to cause a
**false negative** is quiet: add the adversary's own indicator to a whitelist, or
mark their infrastructure as known-good, and the detection silently stops firing.
A capable actor chooses suppression. That means the indicator supply chain is worth
attacking precisely because success is invisible, and "no alerts" is not evidence of
no compromise.

**How to use it.** Require two distinct upstreams for any maliciousness claim
(`supports_malicious_claim` is only true for `corroborated`). Treat whitelist
changes as security events, not housekeeping.

---

## What the four have in common

Each control increases *coverage* and none of them increases *integrity*. Coverage
is how much you can see; integrity is whether what you see is true. Live response
sees more of a system that may be lying. Independent firmware acquisition widens
coverage only if the path is genuinely independent. Baselines calibrate against a
system that may have been compromised when calibration ran. Intelligence aggregates
sources that may share one poisoned origin.

So the correct reading of a detection stack built from these four is: it is a
breadth instrument. Integrity comes from exactly one place, out-of-band evidence the
subject cannot author, and there is very little of it available on a machine you
cannot physically touch.

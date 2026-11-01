# Module proposal: network observation

**Status: prototype.** Designed before implementation, per rule R2. The same
review gate as the rest of this project applies: nothing here has been attacked by
anyone but its author, and the privacy constraints in §4 are requirements, not
suggestions.

---

## 1. Purpose and scope

Record what a suspect host talked to, when, and under whose claimed identity, so
that a case file can answer four questions after the fact:

1. **What did it talk to?** destinations, resolved names, volumes, timing.
2. **Which process claims that traffic?** image, parent chain, user, session.
3. **Is that claim believable?** see §3, this is the hard part.
4. **What kind of destination is it?** internal, external, known, first-seen.

This is **not** an IDS, not a proxy, and not a packet capture tool. It is a
recorder with an explicit honesty model about what it can and cannot attribute.

### What it records

| Record | Fields |
|---|---|
| DNS event | timestamp, host, qname, qtype, rcode, answers, resolver, claimed pid/image |
| Flow event | 5-tuple, protocol, start/end, bytes out/in, claimed pid/image/parent chain, optional URI and command line, source (`host` or `wire`) |
| Process node | pid, ppid, image path, image hash, user, session |
| Destination classification | address, network kind, organisation, category, first-seen, confidence |

### What it deliberately does not record

No payload bytes. No TLS plaintext. No credentials, cookies or tokens. No full
URLs with query strings (path retained because detection needs it; query strings
routinely contain tokens). No capture of traffic that belongs to anyone other than
the authorised subject.

That last one is a scope boundary, not a technical limitation: a recorder that
silently captures a bystander's session is a legal and ethical problem wearing an
engineering costume.

---

## 2. The attribution problem, stated plainly

This is the reason the module exists in this shape.

On a clean host, a socket's owning process is a fact: the kernel reports it and
the kernel is trustworthy. On a host infected with any of the three families in
this project, **it is not a fact, it is a claim by a potentially compromised
operating system.** BlackLotus injects into `winlogon.exe`. MoonBounce injects
into a `SVCHOST.EXE -K NETSVCS` instance. In both cases, honest OS-level
accounting says the traffic belongs to a legitimate, Microsoft-signed component,
because that is precisely what the malware arranged.

Therefore every flow carries an attribution tier:

| Tier | Meaning | How it is obtained |
|---|---|---|
| `wire_only` | The flow was observed on the network, with no host-side claim | SPAN/TAP, firewall or resolver logs |
| `claimed_only` | The host asserts an owner; nothing external confirms it | Endpoint API, ETW, eBPF |
| `corroborated` | Wire and host agree on the 5-tuple within a time window | Join of the two |
| `conflict` | Wire and host disagree about *who* or *whether* | Join, then compare |

**The signal is the delta, not the record.** A flow that exists on the wire but
not in host accounting means the host is blind, misconfigured, or hiding
something. A flow the host reports that never appears on the wire means the
accounting is being fabricated, spoofed, or never left the machine. Either is
worth more analyst attention than a hundred ordinary rows.

Corollary that must not be softened: **`corroborated` means the two sources
agree, not that the attribution is true.** If an implant hooks both the socket
layer and the accounting the kernel exposes, both lie consistently. Wire
observation cannot be forged by the endpoint, which is why it is the reference
point, but wire observation cannot name a process on the host. The pair is
stronger than either; neither is ground truth.

---

## 3. Correlation model

```
        endpoint records                    wire records
   (pid, image, parent chain)          (5-tuple, bytes, timing)
              │                                  │
              └──────────► join ◄────────────────┘
                     match keys: dst_ip, dst_port, proto,
                     src_ip/src_port where available,
                     |Δt| ≤ tolerance (default 2 s)
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   matched pair         wire only              host only
   compare image    unattributed_egress      phantom_claim
        │
   agree / conflict
        │
   corroborated / attribution_conflict
```

Clock discipline is a hard dependency. Correlation is only as good as the skew
between sources, so each source carries its own clock reference and the join
records the observed offset. A 30-second skew turns every match into a mismatch,
and a silent one at that.

---

## 4. Privacy and authorisation constraints

Network metadata is surveillance data. It reveals who someone contacted, when, for
how long, and how much. It is treated as sensitive by default.

| Constraint | Requirement |
|---|---|
| Authorisation | Written scope naming the subject hosts and the time window, before collection starts |
| Minimisation | Metadata only, per §1; no payloads, no query strings, no credentials |
| Third parties | Traffic not belonging to the subject is excluded at capture, not filtered later |
| Retention | Records expire on a stated schedule; expiry is logged like any other state change |
| Access | Same access control as the evidence vault: named analysts, per-case, audit on read |
| Transparency | If the organisation has staff-monitoring obligations, recording is disclosed in the manner its policy requires |
| Derivative risk | Destination classifications and beacon scores are inferences; they must not be presented as findings of fact about a person |

These are engineering requirements in the same sense as the crypto is: a recorder
that satisfies §2 and ignores this section is not fit to deploy.

---

## 5. Destination classification

Two different kinds of claim, kept separate because they have different error
models:

**Deterministic (no feed, no error).** Computed from the address itself with
`ipaddress`: loopback, link-local, private (RFC 1918), CGNAT (100.64.0.0/10),
unique-local (fc00::/7), multicast, documentation, benchmark, reserved,
unspecified. These are arithmetic facts, tagged `confidence: deterministic`.

**Asserted (feed, error, freshness).** ASN and organisation, category
(CDN, cloud, mail, sinkhole, newly-registered), reputation. Every record carries
the feed name, its version or timestamp, and an age. A two-year-old category label
is not evidence.

**Derived (this host, this window).** First-seen for this host, first-seen
globally within the case, and whether the destination was ever contacted by any
other host in the estate. This is the most useful signal in practice and needs no
threat feed at all.

The module must never collapse these into a single "reputation" number. A
deterministic fact dressed up as a reputation score is how analysts end up arguing
about arithmetic.

---

## 6. Beaconing

Periodic check-in is the most durable C2 property, because it survives domain
rotation, TLS, and payload changes. The score is computed over inter-arrival
times, and its limits are stated with it:

- intervals must number at least 4 to say anything;
- regularity is the fraction of intervals within ±20% of the median;
- dispersion is the coefficient of variation, which penalises jitter;
- `score = regularity × max(0, 1 − CV/0.5)`.

What it can conclude: "this destination was contacted on a near-constant schedule
for N intervals", which is a legitimate lead.

What it cannot conclude: intent. Cron jobs, NTP, telemetry agents, updaters and
health checks are all periodic. A high score is a reason to look, never a
conclusion. The score is also trivially defeated by jitter, which any competent
operator applies, so a low score means nothing at all.

---

## 7. Detections derived from documented family behaviour

Each rule cites the same evidence used in the main report, with the same caveat:
these are shapes taken from published analysis, not validated against samples.

| Rule | Condition | Basis |
|---|---|---|
| `blacklotus_winlogon_egress` | claimed image is `winlogon.exe` and destination is external | BlackLotus injects a downloader into `winlogon.exe`; it has no legitimate reason to originate traffic [CONFIRMED in report §4.6] |
| `blacklotus_gate_path` | URI path is `/API/hpb_gate.php` | Documented C2 path [CONFIRMED, ESET] |
| `blacklotus_ip_probe` | DNS query `api.ipify.org` from `winlogon.exe` | Documented public-IP check [CONFIRMED, ESET] |
| `moonbounce_netsvcs_fetch` | claimed image is `svchost.exe` with `NETSVCS` in its command line, and it fetches a binary over HTTP | Documented injection target and stage fetch [CONFIRMED, Kaspersky technical details p.8] |
| `lojax_agent_egress` | claimed image is `rpcnetp.exe` and destination is external | Trojanised Computrace agent [CONFIRMED, ESET] |
| `attribution_conflict` | wire and host disagree on image or existence | This module's own model, §2 |
| `beaconing` | score ≥ threshold on ≥ 4 intervals | §6 |

Note the double edge on the first three: they depend on **claimed** identity, which
§2 says is untrustworthy exactly when these families are present. That is why the
`attribution_conflict` rule outranks all of them. If the implant is hiding, the
named-process rules see a legitimate process doing legitimate-looking things, and
only the divergence rule notices.

---

## 8. Failure modes

| # | Failure | Mechanism | Mitigation | Residual |
|---|---|---|---|---|
| N1 | Recorder runs on the compromised host | Endpoint agent is downstream of the implant; its records are attacker-influenced | Prefer out-of-band capture; treat host records as claims, never facts | An implant that hooks both socket and accounting lies consistently |
| N2 | DNS invisible | Client uses DoH/DoT, or ECH hides SNI; resolver logs never see the query | Capture at the resolver *and* the endpoint; record which resolver was used; flag unknown resolves | Encrypted resolution to an external resolver is simply not observable |
| N3 | NAT / CGNAT destroys host attribution | Many hosts share one egress address | Record NAT translations if available; otherwise mark destination attribution as shared | Without NAT logs, external IP attribution is host-ambiguous |
| N4 | Clock skew breaks the join | Sources drift; VM pause; timezone confusion | Per-source clock reference, record observed offset, timestamp everything in UTC epoch | Skew beyond tolerance silently converts matches into two one-sided findings |
| N5 | Volume swamps the analyst | Metadata at scale is enormous | Aggregation by destination, first-seen suppression, retention limits | Aggregation hides the single anomalous flow |
| N6 | Privacy overreach | Easy to capture more than authorised | Minimisation at capture (§4) | A determined operator can widen scope; audit of scope changes is the control |
| N7 | False positive from periodic legitimate traffic | NTP, updaters, telemetry | Beacon score never presented as a verdict | Analyst time wasted; no way to fully suppress |
| N8 | Classification treated as fact | Feed labels presented as ground truth | Three confidence tiers kept separate in the schema | Downstream consumers may still flatten them |
| N9 | IPv6 rotation and privacy addresses | One host appears as many addresses | Join on interface/MAC where available, not just address | Privacy extensions genuinely defeat long-term address attribution |
| N10 | Records tampering | Evidence altered after the fact | Records sealed through the vault: hash-chained audit, content-addressed store | Same limits as the vault (see review W2/W3) |

---

## 9. Open questions

1. What is the correct retention default for metadata that reveals contacts but not
   content? Needs a policy answer, not an engineering one.
2. Can a beacon score be made robust to moderate jitter without raising the false
   positive rate on cron-like legitimate traffic? Requires a labelled dataset that
   this project does not have.
3. Does wire-vs-host divergence actually fire on BlackLotus in practice, or does
   its downloader use ordinary WinHTTP paths that a kernel callback reports
   normally? Only a controlled test on bench hardware answers this (see
   `HARDWARE_TEST_QUESTIONS.md`, and note it needs an isolated network, not the
   internet).
4. Is there a defensible way to record DNS answers when the client uses DoH? The
   honest current answer is no, and stating that is better than a partial solution
   that looks complete.

---

## 11. Network context as a policy selector

An observed association (BSSID, SSID, security mode) selects which collection,
retention and custody policy applies to evidence gathered on that network. This is
the same shape as enterprise Wi-Fi profiles keyed on SSID or EAP realm, and it is
sound — with one hard boundary.

### 11.1 BSSID is a selector, never key material

A BSSID is 48 bits, transmitted in the clear in every beacon and probe response,
observable from outside the building, and clonable in seconds. Deriving, seeding
or "strengthening" a key with it yields a key every nearby radio already knows.
`tests/test_netpolicy.py` demonstrates it directly: two independent hosts hashing
the same BSSID land on identical bytes.

Where per-network keys are genuinely wanted, the key must come from a CSPRNG on
the host and be **tagged** with the network context, not derived from it. The
envelope records the tag; the key derives from entropy.

### 11.2 Selection is fail-safe because the BSSID is attacker-controlled

An evil-twin AP chooses the BSSID it presents, so "we are on the office network"
is a claim by whoever is radiating. Therefore evaluation is ordered so every
disqualifier is checked before any credit is given, and a BSSID can only ever lose
trust, never earn it alone:

| Condition | Result |
|---|---|
| No valid BSSID, or multicast bit set | `untrusted`, fail-safe |
| Registry records the network as hostile | `hostile` |
| BSSID locally administered (randomised) | `untrusted` — hotspots and spoofed APs |
| Security mode without server authentication (open, WEP, WPA2-PSK) | `untrusted` — a shared secret proves nothing about the network |
| EAP offered but server certificate not validated | `untrusted` — evil twin indistinguishable |
| Authenticated, but registry does not know the BSSID | `ambiguous` |
| Authenticated, known, but no independent corroboration | `ambiguous` |
| Authenticated, known, corroborated, and DHCP domain contradicts registry | `ambiguous` |
| Authenticated, known, corroborated | `managed` |

Corroborating factors are things the AP does not get to assert alone: gateway MAC
consistency with the registry, DHCP domain matching expectation, prior observation
of that BSSID in the estate.

### 11.3 What the policy may and may not gate

| May gate | Must never gate |
|---|---|
| Collection depth | Key release or decryption authorisation |
| Retention period | Whether a sample may be preserved at all |
| Custody threshold (2-of-3 vs 3-of-5) | Whether the audit chain is verified |
| Whether evidence may transit the network | The operator's ability to record |

Note the direction of the `hostile` policy: it preserves *more* evidence under
*tighter* custody, rather than discarding. A containment system that responds to
a hostile network by deleting evidence has inverted its purpose.

### 11.4 Recording the decision

`envelope_context()` writes the BSSID, its structural flags, the selected policy,
the reasons, the corroborating factors and a fail-safe marker into the evidence
envelope. A reviewer can then see which policy was in force at capture and whether
it was appropriate — checkable later, instead of asserted in a report.

### 11.5 Open questions

1. How stale may the BSSID registry be before "not hostile" means nothing? Needs a
   policy decision, and a compromise between coverage and false confidence.
2. Should a *managed* network relax custody at all, given that a managed network
   can still be compromised? The current answer (2-of-3 instead of 3-of-5) is a
   judgement, not a measurement.
3. Client-side MAC randomisation is irrelevant to BSSID mapping, but AP-side
   BSSID rotation on mesh networks will fragment the registry. Untested.

## 10. Status

Design complete, implementation a prototype, review outstanding. Added to the
claims ledger under its own IDs, with `verification: independent` only for
behaviour this repository's tests actually exercise.

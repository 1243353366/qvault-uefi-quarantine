# Threat intelligence and adversary disruption

Release **0.13.12**, branch `feature/threatintel`, not merged.

Three questions, kept apart on purpose: **what software is operating** (the malware evidence graph), **what infrastructure it depends on**, and **how the operation finances itself**. They are separated because a wallet in a sample and a wallet in an advertisement support "related artefacts", not "this person runs that device", and a module that blurs the two produces confident nonsense.

This module is analysis and packaging. It has no blockchain client, no exchange data and no live feeds; it reasons over evidence somebody else lawfully obtained.

## The five dimensions

| Dimension            | Contents                                           | Usual passive source                                 |
| -------------------- | -------------------------------------------------- | ---------------------------------------------------- |
| Infrastructure       | Domains, hosting, IPs, C2                          | Passive observation, provider disclosure             |
| Distribution         | Telegram channels, Tor services, delivery          | Published reporting, platform abuse records          |
| Financial            | Wallets, transactions, payment routes              | Public ledger, exchange disclosure with lawful basis |
| Technical            | Sample hashes, certificates, reused artefacts      | Sample analysis, certificate transparency            |
| Evidence correlation | Provenance, timestamps, independence, alternatives | This module                                          |

## The doctrine is enforced, not documented

| Rule                       | Where it is enforced                                                                                                                                 | Test                                                     |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| No active collection       | `add` refuses probe, forced-rotation, credential-use, purchase, wallet-interaction and intrusion sources; the module contains no network code at all | `test_collection_sources_are_refused`                    |
| No default for unknowns    | an unrecognised source, claim or entity kind raises rather than being trusted                                                                        | `test_an_unknown_source_has_no_default`                  |
| No independence laundering | the grade comes from provenance roots, so four rows derived from one report count once                                                               | `test_four_rows_from_one_root_are_still_one_observation` |
| No attribution verdict     | per-claim ceilings cap operator, wallet and proxy attribution at HYPOTHESIS, and the output has no identity field                                    | `test_operator_attribution_never_exceeds_hypothesis`     |
| No retaliation             | `disruption_plan` emits report/notify/preserve/submit against named external channels, and refuses any other verb                                    | `test_disruption_is_reporting_only`                      |

Sources refused outright: `active_probe`, `credential_use`, `deception_against_operator`, `forced_rotation`, `intrusion`, `purchase`, `wallet_interaction`. In the US, lawful reporting runs through the FBI IC3 and the relevant CERT; nothing in this module contacts anyone.

## Claim ceilings

| Claim                         | Highest grade passive evidence can reach |
| ----------------------------- | ---------------------------------------- |
| `infrastructure_relationship` | CORROBORATED                             |
| `distribution_relationship`   | CORROBORATED                             |
| `financial_relationship`      | CORROBORATED                             |
| `malware_family_correlation`  | CORROBORATED                             |
| `campaign_membership`         | INFERRED                                 |
| `wallet_ownership`            | HYPOTHESIS                               |
| `operator_attribution`        | HYPOTHESIS                               |
| `proxy_operator_attribution`  | HYPOTHESIS                               |

`CONFIRMED` is absent from every attribution row by construction. It is not that attribution is impossible; it is that this module cannot do it, and a ceiling is a cheaper safeguard than an analyst's discipline at 2am.

## Lawful disruption avenues

| Artefact           | Action   | Channel                                           |
| ------------------ | -------- | ------------------------------------------------- |
| `domain`           | report   | registrar or hosting provider abuse desk          |
| `ip`               | report   | hosting provider abuse desk or CERT               |
| `certificate`      | report   | certificate authority revocation desk             |
| `sample_hash`      | submit   | malware research community and AV vendors         |
| `wallet`           | submit   | exchange compliance and investigators             |
| `smart_contract`   | report   | chain-analytics provider and investigators        |
| `telegram_channel` | report   | Telegram abuse reporting                          |
| `tor_service`      | preserve | preserve evidence, then report to law enforcement |
| `hosting_provider` | notify   | provider abuse desk                               |
| `exchange`         | submit   | exchange compliance team                          |
| `proxy_service`    | report   | provider abuse desk                               |

## Ledger pointers: where a takedown is not a fix

If a sample resolves its infrastructure through a public ledger, blocking the domains removes the current C2 and leaves the rediscovery path intact. `deleted_domains_are_not_enough` reports that dependency as `blockchain_dependent: true` with grade `INFERRED`, and returns `UNKNOWN` with an explicit "absence of evidence" note when no pointer is observed. The second case matters: no pointer is not a clean sample.

## What a package contains, and what it refuses to conclude

Hashed artefacts with provenance, the graded graph, hypotheses, one competing explanation per hypothesis, and a list of what the package does not establish: who controls a wallet, domain or account; that related artefacts share an operator; that a device belongs to any identified person. A package that omits the competing explanation is refused.

## Two bugs this module found in itself

A derived observation once hashed to its parent's id, so a two-step derivation made the provenance walk follow itself and the test **hung instead of failing**. Identity now covers every field, and the walk refuses cycles. Both are tested.

The tests were written from the analyst's side of the desk rather than the attacker's: try to launder one source into four, promote a wallet to an owner, and turn a rotation into an attribution. Twenty-four tests; the ceilings hold.

## The research direction this page takes, and why

Two directions were on the table: **A**, the financial trail, and **B**, the operational graph.

**B first.** The financial trail dead-ends exactly where the doctrine requires it to: exchange records
need lawful process, so a passive-only pipeline produces wallet clusters with no subject attached and
stops. The operational graph is buildable from passive observation, and every disruption avenue in the
table above is technical. Finance is the second pass, and its job is to tell you which of the nodes you
already mapped are worth reporting on.

The one exception worth carving out early is the ledger-pointer case: when infrastructure is fetched
from a public chain, the financial and technical questions collapse into the same artefact, and a
domain blocklist stops being a fix.

## Why this is off `main`

Attribution and financial analysis carry a different legal reading from the containment engine, and a module that names wallets and channels is a different publication than one that quarantines firmware. It stays on a branch until that reading is settled deliberately. It is in the page registry, so merging publishes it and the sitemap lists it; `robots.txt` cannot index an unmerged branch, because there is nothing built to crawl.

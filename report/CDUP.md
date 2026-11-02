# CDUP: Cryptographic Data Usability Protection

Release **0.17.0**. Built on `feature/cdup`, held there until the legal reading was
settled, and merged in this release; the reasoning is at the end of this page.

**Objective.** Assume an attacker acquires the payload. Minimise what they can recover from
it.

The premise is not paranoia. Infostealers are sold as malware-as-a-service, so an attacker
who cannot write malware can rent collection, and Recorded Future's 2025 data puts the yield
at roughly 87 stolen credentials per compromised device. The interesting question is not
whether the payload is stolen but what a stolen payload is worth.

## Where encryption helps, and where it cannot

| Stage                  | What the attacker gets                                                                            | Does CDUP protect it                                                                    | Grade                     |
| ---------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------- |
| 1. Before encryption   | A keylogger, screen recorder or input hook reads plaintext the application has not encrypted yet. | **No.** CDUP never sees this data.                                                      | CONFIRMED (limitation)    |
| 2. During processing   | Malware reads application memory while a document is decrypted for use.                           | **Partly.** The window is bounded and audited; memory is not zeroised.                  | CORROBORATED (limitation) |
| 3. After encryption    | The attacker copies ciphertext without the key.                                                   | **Yes.** This is the working case, tested from the attacker's side.                     | CONFIRMED                 |
| 4. During transmission | The attacker intercepts the encrypted payload.                                                    | **Yes, if the authority is not co-located.** Depends on deployment, not on this module. | CORROBORATED              |

## The properties, and where each one lives

| Property                            | Implemented by                                                                            | Grade     |
| ----------------------------------- | ----------------------------------------------------------------------------------------- | --------- |
| Application-level encryption        | `cdup.put` encrypts before anything reaches the store                                     | CONFIRMED |
| Per-object encryption keys          | `put` draws a fresh DEK per object; nothing is shared                                     | CONFIRMED |
| Hardware-backed key protection      | **not implemented.** The authority is a 0600 file; an HSM is deployment work              | UNKNOWN   |
| Explicit decryption authorization   | `KeyAuthority.issue` / `open_dek`; nothing decrypts without a capability                  | CONFIRMED |
| Short-lived decryption capabilities | TTL checked against a clock; expiry is a refusal                                          | CONFIRMED |
| Key separation                      | `assert_separated` refuses a nested tree; capability MACs use an HKDF subkey, not the KEK | CONFIRMED |
| Authenticated encryption            | AES-256-GCM per chunk, AAD-bound to the object id, so ciphertext cannot be relabelled     | CONFIRMED |
| Access auditing                     | `cdup.seal`, `cdup.issue`, `cdup.open`, `cdup.deny` in the hash-chained log               | CONFIRMED |

## The load-bearing control is the authority, not the cipher

```
plaintext ──▶ AES-256-GCM (fresh DEK) ──▶ ciphertext ──▶ store  (no key material)
                     │
                     └── DEK wrapped under the KEK ──▶ held by the authority

decrypt:  capability ──▶ authority checks mac, expiry, binding, replay ──▶ DEK
```

A machine that holds the store cannot decrypt it. That is the whole design, and it is only
true while the authority is somewhere the endpoint cannot read. If the authority runs on the
same host and answers whatever asks, the separation is an envelope with extra steps, and this
page should be read as describing an envelope.

## Refusals are intentionally indistinguishable

Expired, forged, replayed and wrong-object capabilities all raise the same string,
`decryption not available`. The reason is written to the audit log, which an authorised
observer reads, rather than to the caller, who may be probing. A test asserts that all four
messages are byte-identical, because a helpful error is an oracle.

## What is tested, from the attacker's side

Thirteen tests in `qvault/tests/test_cdup.py`: roundtrip; the store contains no key material;
expired refused; capability for another object refused; forged lifetime refused; replay refused;
repeatable capability when explicitly asked for; ciphertext swapped between objects refused;
capability from a rival authority refused; identical refusals; nested authority tree refused;
refusals audited; default lifetime bounded.

## Open tests this page cannot pass

| Question                                            | State                                                                                                                                                                         | Grade                  |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| Does a stolen session cookie defeat the boundary?   | Not tested. There is no network API or session authentication here, so a cookie cannot reach the authority at all - the question is deferred, not answered.                   | UNKNOWN                |
| Is plaintext recoverable from memory during `get`?  | Almost certainly yes. Python strings and buffers cannot be reliably zeroised; the capability bounds when decryption happens, not what an observer with memory access can see. | HYPOTHESIS             |
| Does the separation survive a compromised endpoint? | Only if the authority runs where the endpoint cannot read it. Same-host authority that cooperates automatically is architectural decoration.                                  | INFERRED               |
| Does this help against a keylogger?                 | No. Stage 1 is untouched, and no amount of encryption after the fact recovers it.                                                                                             | CONFIRMED (limitation) |

## Why this is on a branch, and what robots.txt can and cannot do

This subsystem invites a different legal reading from the rest of the repository: it is key
management for data whose owner is not necessarily the person running it. Nothing here
collects, decrypts or transmits data belonging to anyone else, and no network interface is
implemented - but the capability model is exactly what a lawful-access feature would need, so
it stays off `main` until that is thought through rather than assumed.

It is in the page registry, so it joins the sitemap the moment the branch is merged and the
site rebuilds. **`robots.txt` cannot index a branch.** Crawlers read the built site; a page
that is not published has nothing to crawl, and adding a path to `robots.txt` on `main`
would point at a 404. Merge is the publication step, not a robots entry.

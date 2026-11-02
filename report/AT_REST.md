# Records sealed at rest

Release **0.17.0**. Module `qvault/atrest.py`, tests `qvault/tests/test_atrest.py`.

Seven properties, each written as behaviour a test can attack. The interesting part of this page is not the list; it is where the list is weaker than it sounds, which is stated per row rather than in a footnote at the end.

## The properties, as enforced

| Property                   | How it is enforced                                                                                                         | Test                                                        |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| `local_encryption`         | records are sealed in memory and written sealed; there is no code path that writes plaintext                               | `test_a_record_round_trips_and_leaves_no_plaintext_on_disk` |
| `authenticated_encryption` | AES-256-GCM; associated data binds the record id and schema, so ciphertext cannot be relabelled                            | `test_ciphertext_cannot_be_moved_to_another_record`         |
| `key_separation`           | `assert_separated` refuses a key root inside the record tree, before anything is created                                   | `test_keys_inside_the_record_tree_are_refused`              |
| `hardware_backed`          | `TpmProtector` requires `/dev/tpmrm0`; without it, construction fails instead of pretending                                | `test_a_tpm_is_used_when_present_and_refused_when_absent`   |
| `rotation_and_revocation`  | rotation re-wraps DEKs and leaves ciphertext byte-identical; revocation makes records unreadable while leaving them intact | `test_rotation_rewraps_without_touching_ciphertext`         |
| `integrity`                | hash-linked chain over content identity; edit, delete and reorder all fail verification                                    | `test_the_chain_catches_edit_delete_and_reorder`            |
| `fail_closed`              | a protector that cannot wrap raises and nothing is written or replaced                                                     | `test_a_failing_protector_writes_nothing_at_all`            |

## Fail closed, concretely

`SealedVault.write` seals first and persists second. If the protector cannot wrap - device missing, hardware error, revoked key - the call raises and nothing is written, replaced or left behind: no plaintext, no partial file, no degraded "write it unprotected and fix it later". A test drives a protector that always fails and then scans the whole temporary tree for the payload marker; it is not there.

The same rule governs reads. A record that fails authentication raises. It is never returned partially, and the caller cannot distinguish "tampered" from "wrong key" beyond the error class, which is deliberate.

## Hardware backing, honestly graded

`TpmProtector` requires `/dev/tpmrm0` and refuses to construct without it. Its backing grade is `HYPOTHESIS`, not `CONFIRMED`, even on a machine that has one: no attestation is captured, so "this key is bound to these PCRs on this platform" is a claim this code cannot support. The software protector is `HYPOTHESIS` and must be requested explicitly, because a wrapping key on the same host as the ciphertext is an envelope, not a boundary.

## Rotation and revocation

Rotation mints a new key id and re-wraps each record's DEK under it. Ciphertext and nonce are unchanged, byte for byte, and a test asserts that. This is why the key id is bound by the wrapped key rather than by the payload's associated data: binding it to the payload made rotation impossible without re-encrypting every record.

Revocation is a deliberate destruction of availability. The ciphertext is untouched, so a revoked record stays on disk exactly as it was; it simply cannot be opened. Revoking the last live key is permitted, and sealing afterwards fails closed rather than silently falling back to another key.

## Integrity

Records are hash-linked in sequence order and the head digest is stored separately, so an edit, a deletion, a reordering or a truncation each fail verification. The chain commits to **content identity** - record id, sequence, nonce and ciphertext - not to the whole envelope, because rotation changes the envelope's key metadata and must not invalidate the chain it did not touch.

Records are append-only. Rewriting an existing id is refused, so a revision is a new record with its own sequence number and the chain never loses what it previously attested to.

## Three bugs this layer produced before it worked

The key id was originally bound into the payload's associated data, so every rotation broke decryption: correct-looking, and it made the two properties mutually exclusive.

The head file stored the record count as the next sequence number, so every record claimed sequence zero and the chain reported a gap on the second write.

The chain hashed whole envelopes, so a rotation - which rewrites only the wrapped DEK - broke every link. All three were caught by tests that rotate, revoke and reorder rather than round-tripping once.

## What this does not claim

- **Memory.** Plaintext exists inside the process during `seal` and after `open`. Python cannot zeroise a `bytes` object, so a reader of this process's memory reads the record. This layer protects data at rest.
- **A same-host authority.** A software protector on the host holding the ciphertext is defeated by anything that can read its key root. Real separation is another host, an HSM or a TPM with attestation.
- **TPM attestation.** Not captured, therefore not claimed.
- **Recovery.** A revoked or lost key means those records are gone. There is no escrow here, and adding one would weaken the property that makes revocation meaningful.

## Using it

```python
from qvault.atrest import SealedVault, SoftwareProtector, TpmProtector

protector = TpmProtector('/var/lib/qvault/keys')        # refuses without a TPM
vault = SealedVault('/var/lib/qvault/records', '/var/lib/qvault/keys', protector)
vault.write('record-0001', evidence_bytes)
vault.rotate()
vault.verify_chain()['ok']
```

## Why this holds up

Every property above maps to a named test that attacks it rather than exercising it, the aggregate claims are graded, and the gaps are listed next to the guarantees instead of being discovered by an examiner. The one thing this page will not do is describe a software protector on a shared host as though it were hardware separation.

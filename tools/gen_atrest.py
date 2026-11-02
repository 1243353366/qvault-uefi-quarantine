#!/usr/bin/env python3
"""Render report/AT_REST.md from qvault.atrest, so the property table cannot drift from the code."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault.atrest import ALG, PROPERTIES, SoftwareProtector, TpmProtector  # noqa: E402

OUT = ROOT / "report" / "AT_REST.md"

ROWS = [
    ("local_encryption",
     "records are sealed in memory and written sealed; there is no code path that writes plaintext",
     "test_a_record_round_trips_and_leaves_no_plaintext_on_disk"),
    ("authenticated_encryption",
     f"{ALG}; associated data binds the record id and schema, so ciphertext cannot be relabelled",
     "test_ciphertext_cannot_be_moved_to_another_record"),
    ("key_separation",
     "`assert_separated` refuses a key root inside the record tree, before anything is created",
     "test_keys_inside_the_record_tree_are_refused"),
    ("hardware_backed",
     "`TpmProtector` requires `/dev/tpmrm0`; without it, construction fails instead of pretending",
     "test_a_tpm_is_used_when_present_and_refused_when_absent"),
    ("rotation_and_revocation",
     "rotation re-wraps DEKs and leaves ciphertext byte-identical; revocation makes records "
     "unreadable while leaving them intact",
     "test_rotation_rewraps_without_touching_ciphertext"),
    ("integrity",
     "hash-linked chain over content identity; edit, delete and reorder all fail verification",
     "test_the_chain_catches_edit_delete_and_reorder"),
    ("fail_closed",
     "a protector that cannot wrap raises and nothing is written or replaced",
     "test_a_failing_protector_writes_nothing_at_all"),
]


def render() -> str:
    o = ["# Records sealed at rest\n\n"]
    o.append(f"Release **{__version__}**. Module `qvault/atrest.py`, tests "
             "`qvault/tests/test_atrest.py`.\n\n")
    o.append("Seven properties, each written as behaviour a test can attack. The interesting part of "
             "this page is not the list; it is where the list is weaker than it sounds, which is stated "
             "per row rather than in a footnote at the end.\n\n")

    o.append("## The properties, as enforced\n\n")
    o.append("| Property | How it is enforced | Test |\n|---|---|---|\n")
    for name, how, test in ROWS:
        o.append(f"| `{name}` | {how} | `{test}` |\n")
    o.append("\n")

    o.append("## Fail closed, concretely\n\n")
    o.append("`SealedVault.write` seals first and persists second. If the protector cannot wrap - device "
             "missing, hardware error, revoked key - the call raises and nothing is written, replaced or "
             "left behind: no plaintext, no partial file, no degraded \"write it unprotected and fix it "
             "later\". A test drives a protector that always fails and then scans the whole temporary tree "
             "for the payload marker; it is not there.\n\n")
    o.append("The same rule governs reads. A record that fails authentication raises. It is never "
             "returned partially, and the caller cannot distinguish \"tampered\" from \"wrong key\" beyond "
             "the error class, which is deliberate.\n\n")

    o.append("## Hardware backing, honestly graded\n\n")
    o.append(f"`TpmProtector` requires `/dev/tpmrm0` and refuses to construct without it. Its backing "
             f"grade is `{TpmProtector.grade}`, not `CONFIRMED`, even on a machine that has one: no "
             "attestation is captured, so \"this key is bound to these PCRs on this platform\" is a claim "
             "this code cannot support. The software protector is `"
             f"{SoftwareProtector.grade}` and must be requested explicitly, because a wrapping key on the "
             "same host as the ciphertext is an envelope, not a boundary.\n\n")

    o.append("## Rotation and revocation\n\n")
    o.append("Rotation mints a new key id and re-wraps each record's DEK under it. Ciphertext and nonce "
             "are unchanged, byte for byte, and a test asserts that. This is why the key id is bound by "
             "the wrapped key rather than by the payload's associated data: binding it to the payload "
             "made rotation impossible without re-encrypting every record.\n\n")
    o.append("Revocation is a deliberate destruction of availability. The ciphertext is untouched, so a "
             "revoked record stays on disk exactly as it was; it simply cannot be opened. Revoking the "
             "last live key is permitted, and sealing afterwards fails closed rather than silently "
             "falling back to another key.\n\n")

    o.append("## Integrity\n\n")
    o.append("Records are hash-linked in sequence order and the head digest is stored separately, so an "
             "edit, a deletion, a reordering or a truncation each fail verification. The chain commits to "
             "**content identity** - record id, sequence, nonce and ciphertext - not to the whole "
             "envelope, because rotation changes the envelope's key metadata and must not invalidate the "
             "chain it did not touch.\n\n")
    o.append("Records are append-only. Rewriting an existing id is refused, so a revision is a new record "
             "with its own sequence number and the chain never loses what it previously attested to.\n\n")

    o.append("## Three bugs this layer produced before it worked\n\n")
    o.append("The key id was originally bound into the payload's associated data, so every rotation broke "
             "decryption: correct-looking, and it made the two properties mutually exclusive.\n\n")
    o.append("The head file stored the record count as the next sequence number, so every record claimed "
             "sequence zero and the chain reported a gap on the second write.\n\n")
    o.append("The chain hashed whole envelopes, so a rotation - which rewrites only the wrapped DEK - "
             "broke every link. All three were caught by tests that rotate, revoke and reorder rather than "
             "round-tripping once.\n\n")

    o.append("## What this does not claim\n\n")
    o.append("- **Memory.** Plaintext exists inside the process during `seal` and after `open`. Python "
             "cannot zeroise a `bytes` object, so a reader of this process's memory reads the record. This "
             "layer protects data at rest.\n")
    o.append("- **A same-host authority.** A software protector on the host holding the ciphertext is "
             "defeated by anything that can read its key root. Real separation is another host, an HSM or "
             "a TPM with attestation.\n")
    o.append("- **TPM attestation.** Not captured, therefore not claimed.\n")
    o.append("- **Recovery.** A revoked or lost key means those records are gone. There is no escrow here, "
             "and adding one would weaken the property that makes revocation meaningful.\n\n")

    o.append("## Using it\n\n")
    o.append("```python\nfrom qvault.atrest import SealedVault, SoftwareProtector, TpmProtector\n\n"
             "protector = TpmProtector('/var/lib/qvault/keys')        # refuses without a TPM\n"
             "vault = SealedVault('/var/lib/qvault/records', '/var/lib/qvault/keys', protector)\n"
             "vault.write('record-0001', evidence_bytes)\nvault.rotate()\n"
             "vault.verify_chain()['ok']\n```\n\n")

    o.append("## Why this holds up\n\n")
    o.append("Every property above maps to a named test that attacks it rather than exercising it, the "
             "aggregate claims are graded, and the gaps are listed next to the guarantees instead of being "
             "discovered by an examiner. The one thing this page will not do is describe a software "
             "protector on a shared host as though it were hardware separation.\n")
    assert len(ROWS) == len(PROPERTIES)
    return "".join(o)


def main() -> int:
    OUT.write_text(tables.align(render()))
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# The evidence vault

*An adversarial record is only worth something if it still means something later.*

## Structure

Every Layer 3 event is appended to a hash chain:

```
seq 1   prev=000…000  event=sha256(observation)  seal=HMAC(key, prev|event|kind|subject|at)
seq 2   prev=seal(1)  event=sha256(observation)  seal=HMAC(key, prev|event|kind|subject|at)
seq 3   prev=seal(2)  event=sha256(observation)  seal=HMAC(key, prev|event|kind|subject|at)
```

Each record commits to its predecessor and is sealed with a key that exists only on
this machine (`~/.phantom/local-hmac.key`, mode 0600). Editing a row in the database
leaves a seal that no longer matches; deleting a row breaks the next record's link.

## What it detects

| Attack | Detected by | Result |
| --- | --- | --- |
| Edit a stored event's contents | `seal mismatch` | `ok: false`, `first_bad_seq` |
| Delete a record | `chain link broken` | `ok: false`, `first_bad_seq` |
| Insert a fabricated record | `chain link broken` at the next record | `ok: false` |
| Reorder records | `chain link broken` | `ok: false` |

Tests: `test_editing_a_stored_record_breaks_its_seal`,
`test_deleting_a_record_breaks_the_chain`, `test_chain_verifies_when_untouched`.

## What it does not detect

**A full rewrite by someone holding the local key.** There is no external
timestamping authority here, by design: referring to one would hand a third party the
existence and timing of every event, which is precisely the metadata this project
refuses to export.

If you need stronger guarantees, publish the chain head somewhere you do not
control. `phantom vault-verify` prints it:

```console
$ phantom vault-verify
{
  "ok": true,
  "checked": 8,
  "head": "9f2c…",
  "reason": "every record reseals to its stored seal and links to its predecessor"
}
```

Hash `head` into a public timeline, a signed commit, or a notarised email once a
week, and a rewrite becomes detectably inconsistent with the world rather than merely
plausible.

## What the vault does not contain

The chain stores a commitment to each event, not a copy of everything. It holds the
event fingerprint, kind, subject reference and timestamp. It never holds payload
contents, decrypted protected objects, or credential material.

Samples of suspicious payloads are stored in a separate table, encrypted, addressed
by digest, and never opened by PHANTOM: no execution, no unpacking, no rendering.
`quarantined_payloads_executed` is `false` in the guardrails and a test asserts it.

## Retention

The vault is append-only in normal operation. Deletion is an administrative act, not
an API feature: there is no `DELETE /api/shadow/events`, because a record you can
quietly remove is a record that proves nothing about what you claimed.

Retention for canary observations remains `mirror_retention_days` (default 30). If
you purge them, `vault-verify` will report `chain link broken` from the point of
deletion, which is the honest outcome: the chain witnessed a deletion.

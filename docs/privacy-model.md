# Privacy model

This is the document to read before trusting anything else in the repository. It
describes what PHANTOM stores, what it refuses to store, and how deletion works.

## Principles, in priority order

1. **Do not collect it.** The cheapest protection for data is not having it.
2. **If collected, minimise.** Domains instead of addresses, hashes instead of
   text, booleans instead of details.
3. **If minimised, localise.** It stays on the machine, encrypted at rest.
4. **If localised, deletable.** Every stored thing has a deletion path.

## What is stored

| Data | Where | Why | Lifetime |
| --- | --- | --- | --- |
| Header-derived facts (relay hosts, DKIM domains, auth verdicts) | `nodes`, `edges`, `evidence` | The analysis itself | Until you delete |
| Tracking URLs and the reasons they were flagged | `evidence.payload` | So a claim can be checked | Until you delete |
| SHA-256 of each evidence detail | `evidence.snippet_hash` | Tamper-evident proof without the raw text | Until you delete |
| Consent values (Gmail address, phone, work email) | `consent_records`, encrypted | To honour and to be able to revoke | TTL, default 365 days |
| Egress log (URL + purpose + allowed) | `~/.phantom/egress.jsonl` | The self-audit | Append-only, yours to truncate |

## What is never stored

- **Email bodies.** Parsed in memory, discarded. Only URLs and reasons survive.
- **Message subjects or snippets.** A subject hash at most.
- **Contact names, raw addresses, phone numbers.** Discarded during CSV parsing,
  before matching. The analyzer works on domains only.
- **OAuth refresh tokens in plaintext.** Held by the caller; if persisted, encrypt
  with `crypto.encrypt`.
- **Anything in a third-party service.** There is no PHANTOM backend. There is no
  telemetry, no crash reporting, no analytics.

## Encryption at rest

`~/.phantom/local-hmac.key` holds a 32-byte key, written `0600`, never escrowed,
never transmitted. It serves two purposes:

- **Fernet encryption** for personal values in `consent_records`.
- **HMAC-SHA256 pseudonyms** for stable tokens: `subject_token`, `receipt_hash`,
  and the `domain_token` in exposure results, so a result can be compared across
  runs without revealing the input.

Lose the key and encrypted values become unreadable (`<unreadable: local key
changed>`). That is correct behaviour: no recovery backdoor exists, because a
recovery backdoor is a second way in.

## Retention and deletion

- `Settings.retention_days` (default 90) bounds message-derived rows.
- Consent records carry an explicit `expires_at`; expired grants are treated as
  inactive.
- Revocation nulls the values and marks the scopes revoked in the same write.
- Full deletion: stop the app and remove `~/.phantom/`. There is nothing else to
  clean up, which is the practical benefit of having no server.

## The risk this design does not remove

The graph itself is sensitive. It documents which organisations touch your mail
and, by presence, that you received mail from them. Treat `~/.phantom/phantom.db`
as personal data, because it is.

## Data that belongs to other people

The exposure analyzer deliberately never holds another person's identifiers. It
reads a file you exported, extracts domains, and forgets the rest in the same
function. No upload path exists in the API; there is no endpoint that accepts a
contact list and returns it enriched.

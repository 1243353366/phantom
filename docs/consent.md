# Consent

PHANTOM asks for three things it does not strictly need in order to demonstrate
the analysis, and one thing it does: authorised access to your mail metadata.

## Field by field

| Field | Why it is asked for | Where it goes | Can it be refused? |
| --- | --- | --- | --- |
| `gmail_address` | So a reply about the project reaches you | Encrypted, local `consent_records` | Yes, independently |
| `phone_number` | Optional SMS contact (E.164 only) | Encrypted, local `consent_records` | Yes, independently |
| `work_email` | Optional, for a work-domain reply | Encrypted, local `consent_records` | Yes, independently |

Each requires its own flag: `consent_gmail`, `consent_phone`,
`consent_work_email`. Supplying a value without its flag raises `ConsentError`
and **nothing is written**. That is the whole model: the flag is the permission,
not the fact of typing something into a box.

## The flow

1. The user selects which channels they want, one checkbox each.
2. `POST /api/consent/enroll` with values and flags.
3. PHANTOM stores an encrypted record plus a receipt hash, and returns:
   `stored_fields`, `not_stored`, `channels_authorised`, `purpose`,
   `policy_version`, and how to revoke.
4. The user can read back exactly what is held: `GET /api/consent/{id}`.
5. The user can revoke at any time: `POST /api/consent/{id}/revoke` clears the
   values in the same write.

## What the record contains

```
subject_token    HMAC pseudonym, so rows can be linked without an identifier
gmail_address    encrypted at rest
phone_number     encrypted at rest
work_email       encrypted at rest
scopes           per-field booleans + channels_authorised
purpose          plain text, so the intent travels with the data
policy_version   so a stale grant can be identified after a policy change
expires_at       TTL, default 365 days
revoked_at       set on revocation; values nulled
receipt_hash     HMAC over the canonical grant, provable without decryption
```

## Why a receipt hash

It proves the grant existed and what it covered, without decrypting anything. Two
identical grants produce the same hash, so a duplicate can be detected. It is not
a signature by the user; it is an integrity check on the record.

## Command line

```console
$ phantom enroll --gmail you@gmail.com --consent-gmail
$ phantom enroll --phone +15551234567 --consent-gmail   # refused
refused: phone_number was supplied without permission for it. Nothing was
stored. Each contact field needs its own opt-in.
```

The refusal path is the important one, so it is the one in the docs.

## Mail access consent is separate

Consent to be contacted is not consent to read your mail. Gmail access uses OAuth
with an explicit scope choice (see `docs/gmail-scopes.md`), and the token can be
revoked independently of any contact record.

# Gmail scopes, and why there are two tiers

## The awkward truth

`https://www.googleapis.com/auth/gmail.metadata` gives headers and labels. It does
not give message bodies. Tracking pixels live in bodies. So a tool that claims to
"detect tracking pixels with metadata-only scope" is either misdescribing the
scope or misdescribing the detection.

PHANTOM ships both tiers and names the trade-off.

## Tier 1: metadata (default)

```
scope: https://www.googleapis.com/auth/gmail.metadata
format: metadata
```

Gives: `Received` chains, `DKIM-Signature`, `Authentication-Results`,
`Message-ID`, `From`/`Reply-To`/`Return-Path`, `List-Unsubscribe`, labels.

Enables: sender infrastructure, relay topology, DKIM identity, provider
attribution from routing headers, DMARC posture.

Does not enable: pixels, redirect wrappers, any body-derived analysis.

## Tier 2: body (explicit opt-in)

```
scope: https://www.googleapis.com/auth/gmail.readonly
format: full
```

Adds the HTML alternative, parsed **in memory** and discarded. What survives is
the URL, the reasons it was flagged, and a hash. No body text is stored, indexed
or logged.

This scope grants more than PHANTOM needs in principle, which is exactly why it
is off by default, stated in the consent text, and reported in the UI as a
material increase in trust.

## Never requested

- `gmail.send` — PHANTOM cannot send on your behalf.
- `gmail.modify` — cannot label, archive or delete.
- `gmail.insert` — cannot write into your mailbox.
- `contacts` / `people` — contact data is never fetched. Exposure analysis uses a
  file you export yourself.

## Revocation

`POST /api/consent/{id}/revoke` clears stored values immediately and
`collector/gmail.revoke` hands the token back to Google. Revocation is a
first-class operation, not a section in a policy page.

## State parameter

The OAuth flow requires a `state` value to prevent CSRF on the callback. Generate
a per-session random value, store it locally, and reject callbacks whose `state`
does not match.

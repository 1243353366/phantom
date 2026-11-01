# Negative space

## The premise

What stops appearing is data too. A tracker that disappears from a sender's
messages is a real change in the observable surface, and a log of those changes
is the only way to see the ecosystem move.

## The constraint

PHANTOM can see *that* an observation ended. It cannot see *why*. So it records
the absence and refuses the inference.

Three things that look identical from the outside:

1. The sender removed the tracker (privacy improvement).
2. The sender switched to a tracker that defeats detection.
3. The tracker is still there and the mail client blocked it.

Only the sender knows which. Every `negative_space_events` row therefore carries
`cause_unknown = true`, hard-coded rather than configurable, and every report
repeats:

> Every entry here is an observation of absence. PHANTOM cannot see why something
> stopped appearing, so it does not claim that it did.

## What is recorded

| Change | Meaning |
| --- | --- |
| `tracker_disappeared` | Present in the previous message from this sender, absent in the next |
| `domain_reappeared` | Absent in the previous message, present in this one |
| `redirect_chain_shortened` | Fewer redirect hops than last time |
| `redirect_chain_lengthened` | More redirect hops than last time |

The comparison is always **consecutive messages from the same sender**, not a
global diff. Otherwise an unrelated message would generate noise.

## Why "switched infrastructure" is not a change type yet

Detecting that an organisation moved from provider A to provider B requires
knowing they moved, which requires attributing both to the same organisation.
That is a `hypothesized` claim, so it belongs downstream of the graph rather than
inside the watchdog. It is on the roadmap, gated behind the same caveat rules.

## Failures this design accepts

- A sender who writes once will never produce events.
- Relay hops change constantly and produce chatty, low-value events. They are
  recorded, and they are boring on purpose: the log is a record, not a feed.
- If the corpus is re-ingested out of order, comparisons follow `sent_at`, not
  ingest order. Messages without a `Date` header fall back to ingest time and may
  sort oddly; that is visible in `observed_at`.

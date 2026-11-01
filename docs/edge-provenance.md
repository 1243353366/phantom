# Edge provenance

Every line in the graph is a claim. This document is the contract behind those
claims: which rule produced an edge, how confident it is, and what caveat must be
shown beside it.

## The three classes

| Class | Definition | Ceiling |
| --- | --- | --- |
| `observed` | One authorised message directly shows the relationship. | 0.99 |
| `correlated` | The same technical overlap recurs across independent messages. | 0.85 |
| `hypothesized` | A pattern suggests a relationship that has not been verified. | 0.65 |

Confidence is computed, not asserted:

```
confidence = min(base + 0.1 × (observations − 1), ceiling_for_class)
```

The ceiling is the load-bearing part. No amount of repeated weak signal can push a
hypothesis into sounding like a fact.

## Rules

| Rule | Relation | Class | Trigger | Caveat |
| --- | --- | --- | --- | --- |
| `R-OBS-1` | `serves_tracking_content` | observed | Sender's HTML embedded content from this host and it looked like a beacon | none |
| `R-OBS-2` | `uses_provider` | observed | A host in the message resolves to a registry provider | none |
| `R-OBS-3` | `relayed_through` | observed | Host appears in a `Received:` chain | Shared relay hops are weak evidence |
| `R-OBS-4` | `wraps_links_for` | observed | Link destination was wrapped by a click-tracking redirector | none |
| `R-OBS-5` | `routes_mail_via` | observed | `Reply-To` or `Return-Path` points at a different domain | none |
| `R-COR-1` | `shares_infrastructure_with` | correlated | Two senders each show ≥ `correlation_threshold` independent observations of the same provider | Shared infrastructure does not establish common ownership |
| `R-HYP-1` | `possible_identity_overlap` | hypothesized | One sender identity presented from more than one domain over time | Possible rebrand, migration, or unrelated reuse |

## Why pixels are separate from providers

`serves_tracking_content` is a statement about content delivery.
`uses_provider` is a statement about attribution. They answer different questions
and can disagree: a message can load an image from `ct.pinterest.com` (observed
delivery) while the registry attributes that host to Pinterest (attribution),
without either proving the sender has a commercial relationship with Pinterest.

## Evidence rows

Each `Evidence` row records:

- `kind` — `tracking_pixel`, `click_redirector`, `relay_hop`, `registry_match`,
  `routing_header`, `recurring_overlap`, `identity_continuity`
- `detail` — a sentence a human can check
- `source_ref` — which message, e.g. `eml:01-acme-store.eml:pixel:host`
- `snippet_hash` — SHA-256 of `detail`, so the claim is tamper-evident without
  storing the raw email
- `payload` — structured extras: URL, reasons, size, `message_ref`, `sent_at`

## Enforcement

Two mechanisms keep this honest rather than aspirational:

1. `RelationshipEngine` is the only writer of edges, and it always writes evidence
   in the same call.
2. `tests/test_relationship_engine.py::test_every_edge_has_evidence` fails the
   build if any edge lacks a supporting row.

## Reading an edge in the UI

Clicking an edge must show: the rule, the class, the confidence, every evidence
row with its message reference and timestamp, and the caveat verbatim. An edge
that cannot be explained to the person looking at it should not be on screen.

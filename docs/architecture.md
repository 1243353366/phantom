# Architecture

## Shape of the system

```
                     ┌──────────────────────────────────────────────┐
  Gmail (OAuth) ───▶ │ Phantom Collector                            │
  .eml files    ───▶ │  headers · DKIM · relay chain · pixels · links│
                     └───────────────────┬──────────────────────────┘
                                         │ ParsedEmail
                                         ▼
                     ┌──────────────────────────────────────────────┐
                     │ Tracker Registry                             │
                     │  domain ─▶ provider, category, source        │
                     └───────────────────┬──────────────────────────┘
                                         │ attributions
                                         ▼
                     ┌──────────────────────────────────────────────┐
                     │ Relationship Engine                          │
                     │  rules ─▶ nodes, edges, evidence             │
                     └───────┬───────────────────────┬──────────────┘
                             │                       │
                             ▼                       ▼
            ┌────────────────────────┐   ┌──────────────────────────┐
            │ Phantom Graph          │   │ Temporal Watchdog        │
            │ NetworkX + Cytoscape   │   │ negative space events    │
            └────────────────────────┘   └──────────────────────────┘

                     ┌──────────────────────────────────────────────┐
                     │ Self-audit ── inspects all of the above       │
                     └──────────────────────────────────────────────┘
```

## Data flow for one message

1. **Collect** (`collector/headers.py`). Parse RFC822 headers and the HTML
   alternative. Extract relay hops, DKIM domain/selector, SPF/DKIM/DMARC
   verdicts, routing headers, pixels (`pixels.find_pixels`) and links
   (`pixels.find_links`). Bodies are never persisted.
2. **Identify** (`registry/tracker_registry.py`). Resolve each host against the
   curated registry by longest-suffix match. Unmatched hosts stay unattributed
   on purpose.
3. **Assert** (`engine/relationship_engine.py`). Turn findings into nodes and
   edges, each with at least one `Evidence` row.
4. **Reason** (`engine/relationship_engine.correlate`). Second pass over the
   whole store produces `correlated` and `hypothesized` edges.
5. **Observe change** (`watchdog/negative_space.py`). Compare a sender's
   successive messages and record disappearances and reappearances.
6. **Render** (`engine/graph.py`). Export Cytoscape elements plus summary stats
   and the standing caveats.

## Storage

```
nodes                 key, kind, label, attrs, first_seen, last_seen
edges                 src_key, dst_key, relation, classification, rule_id,
                      confidence, observation_count, caveat
evidence              edge_id, kind, detail, source_ref, observed_at,
                      snippet_hash, payload      ← one row minimum per edge
negative_space_events subject_key, node_key, change, window_from, window_to,
                      before_value, after_value, cause_unknown, note
consent_records       per-field, encrypted, purpose-bound, revocable
self_audit_runs       findings, egress_summary
```

`node.key` is canonical and namespaced: `org:domain:acme-store.com`,
`domain:track.example`, `provider:Mailchimp`, `host:mx.example`,
`dkim:example.com:k1`. Edges reference keys, not ids, so a graph export is stable
across rebuilds.

SQLite is the default because it keeps the whole thing in one file you own.
PostgreSQL is a `PHANTOM_DB_URL` away when the corpus outgrows it.

## Idempotency

`ingest()` is keyed on `(evidence_kind, source_ref)`. Re-ingesting the same
message cannot inflate `observation_count`, which matters because confidence is
derived from it. A provider reached through both a pixel and a redirector in one
message counts once, because one message is one observation.

## Failure behaviour

Fail closed:

| Situation | Behaviour |
| --- | --- |
| Host not on the egress allowlist | `EgressBlocked`, logged, nothing sent |
| Malformed HTML | parser errors swallowed, message still analysed |
| Missing `Date` header | `observed_at` falls back to ingest time |
| Unknown domain | unattributed node, listed in `unresolved()` |
| Personal data without its consent flag | `ConsentError`, nothing stored |
| Local key changed | encrypted values read as `<unreadable>` rather than guessed |

## Testing

```bash
cd backend && pytest -q          # 44 tests, no network, no credentials
```

The suite asserts the invariants rather than the implementation: every edge has
evidence, hypothesized confidence is capped, consent refusals store nothing, no
source file bypasses the egress chokepoint, and contact results never contain a
raw address.

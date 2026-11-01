# Roadmap

## Built and tested (v0.1)

- [x] Header, relay-chain, DKIM and auth-result extraction
- [x] Tracking pixel detection with explainable reasons
- [x] Click-redirector resolution and destination recovery
- [x] Curated tracker/provider registry with per-entry sourcing
- [x] Evidence-backed graph with three edge classes and confidence ceilings
- [x] Correlation and identity-continuity reasoning
- [x] Negative space analysis with `cause_unknown` enforced
- [x] Local contact exposure analysis, domains only, exclusions honoured
- [x] Two-tier Gmail OAuth client (metadata default, body opt-in)
- [x] Per-field revocable consent with encryption at rest
- [x] Egress chokepoint + self-audit + source scanner
- [x] FastAPI surface, CLI, Cytoscape front end, 44 tests
- [x] Docker Compose
- [x] Counter-observation: canary tokens, bounded tarpit, attempt fingerprinting
- [x] Counter-infrastructure graph with campaign clustering, no person-level nodes

## Next

- [ ] OAuth callback handler with `state` validation and token storage under `crypto.encrypt`
- [ ] Incremental sync: remember the last processed `internalDate` per mailbox
- [ ] Bounded, unattended pixel fetch **off by default**, since fetching a beacon is
      itself an observation event
- [ ] Provider migration detection (`infrastructure_switched`), gated behind the
      hypothesized-edge ceiling
- [ ] Registry import from public blocklists, with per-source provenance preserved
- [ ] CSV/JSON export of a report for sharing, with pseudonymous tokens only
- [ ] Front end: time scrubber over negative space events
- [ ] Canary hit alerts through an existing authorised channel (email), opt-in per canary
- [ ] PDF and DOCX canary placement helper, since those are the formats that leak
- [ ] Local ASN table updater that reads a file you download yourself

## Explicitly not planned

- Sending mail or SMS. No endpoint will ever do this.
- Uploading or enriching contact lists.
- A hosted PHANTOM. The privacy model depends on there being no server.
- Identifying individuals, or inferring relationships between people.
- Retaliation against a host that touched a canary, or anything that fires back.
- Attributing corporate ownership beyond publicly documented sources.

## Known limitations

- A sender with one message produces no negative space events.
- The registry is small and curated by hand; recall is low, precision is high.
- Metadata tier cannot see pixels. This is a scope fact, not a bug.
- The source scanner audits PHANTOM's tree, not its dependency wheels.
- No dedupe across Gmail and `.eml` imports of the same message yet.
- Canary attribution stops at the proxy: behind a chain you see the proxy's network.
- The counter-graph and the email graph do not yet share nodes; joining them needs a
  bridge evidence type that does not exist.

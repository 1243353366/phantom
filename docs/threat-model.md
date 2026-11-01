# Threat model

## Assets

1. The user's mailbox metadata and the derived graph.
2. The identifiers of people in the user's contacts.
3. The integrity of the analysis (a wrong graph is worse than no graph).
4. The credibility of the claim "this tool does not surveil you".

## Adversaries

### A1. The sender, and whoever bought the data
Wants to know whether the message was opened, and to correlate identities across
sources. PHANTOM's contribution is visibility, not blocking. Mitigation: pixel and
identifier reporting; no auto-loading, no fetching of pixel URLs.

### A2. A malicious dependency or compromised package
Wants to exfiltrate the graph. Mitigation: the egress chokepoint. Every outbound
call must match `selfaudit/egress_allowlist.yaml` or raise `EgressBlocked`. A
dependency cannot reach the network without either going through that function
(sandboxed only if it imports it), and the source scanner flags direct
`requests`/`socket`/`smtplib` use in our own tree.

*Limit, stated plainly:* a malicious wheel can `import socket` inside its own
package, where our scanner does not look. The self-audit covers PHANTOM's code,
not its entire dependency tree. That is why the dependency list is short and
pinned.

### A3. A local attacker with filesystem access
Gets the database. Mitigation: encrypted values, `0600` key. Not mitigated: an
attacker with the key and the database reads everything. Local disk encryption is
the user's responsibility.

### A4. A hostile input message
Crafted headers to poison the graph, HTML to exploit the parser. Mitigation:
parser exceptions are swallowed per message; no `eval`, no template rendering of
message content; every edge requires evidence, so a single forged header cannot
create a corroborated relationship; hypothesized edges are capped at 0.65.

### A5. The maintainer, and future contributors
The real risk for a project like this is scope creep toward people-tracking.
Mitigation is structural: the four relationship kinds are separate constants, the
exposure analyzer has no upload path, the consent service refuses data without an
explicit per-field flag, and `docs/ethics.md` states the line that changes to this
repository are measured against.

### A6. PHANTOM itself
A privacy tool that adds a surveillance layer defeats its purpose. Mitigation:
`selfaudit` reports declared destinations, scanned bypasses, and observed egress;
the UI shows that report; the allowlist is three hosts.

### A7. A collector that notices it is being studied
A canary tells you that your document was collected, and tells the collector that a
URL resolved. It does not tell them they were detected: unknown, revoked and forged
tokens all return the same valid image, so probing the endpoint yields no
information.

If a collector *does* work it out, the residual risks are denial of the canary
(trivial and acceptable) or deliberate poisoning, by fetching canaries from
unrelated networks to fabricate a campaign cluster. That is why every campaign
cluster is `hypothesized`, capped at 0.65 confidence, and carries a caveat saying
shared tooling is not a shared operator.

The one thing PHANTOM must never do here is respond: no hold long enough to be a
weapon, no outbound request to the requester, no attempt to identify them. A
collection attempt is not an invitation to attack a possibly compromised host.

### A8. The analyst who over-merges
The most likely harm does not come from an outside attacker. It comes from a person
under pressure reading their own graph and deciding that a shared CDN means a shared
owner.

Mitigations: cross-layer edges cannot be written by ingestion at all (`R-SHD-4`
raises `UnconfirmedCrossLayerEdge`); a bridge requires a written rationale naming the
shared observable and a recorded human decision; the resulting edge is capped at 0.65
confidence and carries a caveat naming the innocent explanations. The refusal path is
the only way the layers touch.

Residual risk: a user who confirms a bad bridge anyway. There is no technical control
for that, so the confirmation dialog states the counter-argument instead of asking
"are you sure?".

### A9. Someone with the local key rewrites the vault
The hash chain detects edits, deletions, insertions and reordering. It cannot detect
a full rewrite by someone holding `~/.phantom/local-hmac.key`, because there is no
external anchor.

Mitigation: publish the chain head somewhere outside your control
(`phantom vault-verify` prints it). This is documented rather than automated,
because automating it would export event timing to a third party, which is the
metadata the project exists to protect.

## Threat: the graph being read as an accusation

A `correlated` edge between two organisations is a statement about shared
infrastructure. To a reader determined to see conspiracy, it is proof of
collusion. Mitigations:

- caveat text is attached to the edge, not to a docs page
- `hypothesized` cannot exceed 0.65 confidence
- the report lists "Standing caveats" as its own section
- the legend explains each class in the UI

This is the highest-severity residual risk in the project, and it is a
communication problem more than a technical one.

## Out of scope

- Nation-state adversaries with endpoint access.
- Anonymity against your own mail provider (they already have the mail).
- Attribution of organisations to corporate parents without public sourcing.

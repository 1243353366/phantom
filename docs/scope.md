# Scope

*This document exists to stop PHANTOM from becoming six products.*

## The one product

PHANTOM answers a single question:

> **Which organisations and pieces of infrastructure are in a position to observe
> this person's email, and what is the evidence for each claim?**

Everything in this repo either serves that sentence or is frozen. If a feature cannot
be described as an improvement to that sentence, it belongs in the second list.

## The core loop

The only workflow that receives new work:

1. Ingest authorised message **metadata** (headers, embedded URLs).
2. Identify infrastructure through the tracker registry.
3. Write an edge that cannot exist without its evidence.
4. Render it with the classification and caveat visible.
5. Record what stopped appearing, as an observation.

Five steps. Anything that does not shorten, harden or explain one of those five is
out of scope by default.

## Kept, and actively developed

| Component | Why it is core |
| --- | --- |
| `collector/` | Step 1. Without it there is nothing to map. |
| `registry/` | Step 2. A wrong registry entry produces a wrong claim. |
| `engine/` | Step 3. This is the product's whole credibility. |
| `observations.py`, `rebuild.py` | Keeps step 3 re-derivable. Added at v0.2 as debt payment on an existing step, not as a new module. |
| `engine/graph.py`, `frontend/` | Step 4. Uncertainty that is not visible is not there. |
| `watchdog/` | Step 5. The only thing here that gets better with age. |

## Kept, frozen

Working, tested, and closed to new features. Bug fixes only.

| Component | Frozen at | The rule |
| --- | --- | --- |
| `consent/` | v0.1 | Enrolment, receipt, revocation. No new channels, no new fields. |
| `selfaudit/` | v0.1 | Must keep running on every release. No new audit dimensions. |
| `exposure/` | v0.1 | A local report returned to the requester. Never a graph edge, never stored. |
| `mirror/` (counter-observation) | v0.1 | No new detection, no new signals, no tarpit changes. |
| `shadow/` (ShadowTrace, MirrorLock, vault) | v0.2 | No new event kinds, no new rules, no new correlation math. |

Layer 3 is complete. It has four event kinds, four rules, one sealed chain and one
human-confirmed bridge path, and that is the whole of it. The temptation to add a
fifth event kind is the specific thing this document is here to refuse.

## Out of scope

Not "later". Out.

- A second mailbox provider (Outlook, IMAP, Exchange).
- Any hosted, multi-tenant or "sign in with" version.
- Real-time alerting, push, or anything that creates an obligation to watch.
- A mobile app.
- A browser extension.
- Any people graph, contact graph, or "who knows whom".
- Any second person's data, even with their explicit consent.
- Any attribution: naming a person, an operator, or an employer behind infrastructure.
- Any third-party enrichment API, reputation feed or breach lookup.
- Any active probing of a third party, ever, under any framing.

Each of these is individually reasonable and collectively fatal. A privacy tool that
becomes a platform stops being auditable by the one person whose data it holds.

## Decision record: the five passive telemetry signals

Proposed: `jitter`, `banner`, `headless`, `html`, `origin`. Assessed and **declined
for now**, individually, because they are not the same kind of request.

| Signal | Assessment | Decision |
| --- | --- | --- |
| **HTML** | Already built. `collector/pixels.py` extracts images, anchors and redirect parameters; `R-OBS-1` and `R-OBS-4` already consume them. | Nothing to add. |
| **Jitter** | Derived from timestamps Layer 3 already stores at the decoy endpoint. Not new collection, but "this looked automated" is a new **claim**, and claims are nouns. | Deferred. |
| **Headless** | A derivation over `client_hash` and `client_family`, which are already recorded. Also the most dangerous of the five: every headless signal is a fingerprint, and the project's own line forbids fingerprinting that singles out individuals. | Deferred, last in any queue. |
| **Origin / Referer** | Genuinely new. Request headers are observable at the decoy endpoint and are not collected today. Small, and the only one of the five that would be nearly free. | Deferred. First in line if Layer 3 is ever unfrozen. |
| **Banner** | Reading a service banner means connecting to that service. For hosts you do not own, that is the scanning the restrictions forbid, and it is exactly the line between passive intelligence and active countermeasures. Legitimate only for infrastructure you operate, where you already know the answer. | Declined, not deferred. |

One correction worth keeping: `Origin` and `Referer` are different headers, and
neither is trustworthy. `Origin` is set by browsers on CORS and non-GET requests;
`Referer` is ambient, routinely stripped, and trivially forged by anything that is
not a browser. Either one is a self-asserted claim by the requester, so on the day
this is built it lands as `observed` with a caveat that says so, and it must never
be the sole support for a cross-layer bridge.

Reconsideration gate: all five stay frozen until the v1.0 test below passes, and
then each one still has to displace something already in the "kept" list.

## Decision record: family and other people

Proposed: run the same consent and observation flow for family members.

Three readings, all refused, and the reason is the same in each case.

| Reading | Why it is out |
| --- | --- |
| A family member enrols their Gmail, phone or work email **into this instance** | Their metadata lands in the operator's graph. Every edge then connects one person's infrastructure to another's, and "household exposure" is a claim about someone who is not the operator. |
| A shared view where several people see one graph | Multi-tenant, already out. Also: whose deletion right wins when two people disagree about a shared record? |
| A consent-gated invitation, so the operator can observe a relative who agrees | Consent makes processing lawful. It does not make a map of people into a map of infrastructure. |

The deeper reason, and the one that settles it: this product's only claim is about
infrastructure, and it is credible *because* no node is a person. Introduce people
and every edge inherits an ambiguity the design cannot resolve. Is this edge about a
shared mail provider, or about a household? The system has no way to tell, and a
graph that cannot answer that question is a people graph with a provenance table
attached.

There is a second-order problem consent cannot reach. A household shares an IP, a
device, a router, sometimes an inbox. A relative who consents exposes the others who
did not, and their data arrives through the consented person's records. Consent from
one member is not consent from the household, and consent given to a family member
asking is not the same as consent given freely.

And the recursive audit answers itself: a privacy tool holding a map of your family
has become the thing it audits. That audit runs on every release, so this is not a
line that can be crossed quietly.

### What is allowed, and already true

PHANTOM is single-operator. Each person runs their own instance, on their own machine,
and the report is theirs.

If a relative wants this, they install it and consent for themselves:

```console
$ phantom enroll     # their channels, their consent, their graph, their deletion right
```

Nothing is shared. Nothing merges. There is no hub, no household account and no way to
look across two instances. That is not a limitation waiting on engineering. It is the
product.

## The freeze rule

> A bug fix means **it is broken**, or **it produces a false claim**.

Anything else that adds a noun (a new event kind, a new source, a new node type, a new
report) is a product decision. Product decisions must displace something already in
the "kept" list, in writing, before any code is written. If nothing is displaced, the
answer is no.

## What v1.0 actually means

Not a feature list. One test:

> Ninety days of one real mailbox, ingested through the metadata scope, producing a
> graph where every edge opens to its evidence and a report the owner would send to
> another person.

The demo corpus is a fixture, not a use case. Until a real mailbox produces a report
someone would actually forward, every additional module is decoration.

## Why this is written down

Because the failure mode is not a bad decision, it is a series of reasonable ones.
Six modules at v0.1 became nine at v0.2, and none of that growth came from a user
asking for it. Growth in module count is not growth in usefulness, and the only
reliable defence is a boundary that predates the temptation.

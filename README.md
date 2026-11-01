# PHANTOM

**Privacy Intelligence & Relationship Mapping Platform**

*See the ecosystem that sees you.*

PHANTOM is not another tracker blocker. A blocker hides the tracker. PHANTOM maps
the infrastructure behind it: which organisation sent the message, which third
parties served its content, which provider sits underneath them, and which
relationships that implies. Then it shows you the evidence for every line it
draws, and marks the lines it cannot prove.

```
        reads                      resolves                    draws
  your mail metadata  ──▶  tracker + provider registry  ──▶  an evidence-backed graph
                                     │                              │
                                     ▼                              ▼
                        what changed over time          what is still unknown
```

![PHANTOM graph and counter-observation graph](docs/images/phantom-graphs.png)

*Left: the phantom graph from the demo corpus. Right: the counter-observation graph
after seven simulated canary fetches. Line style encodes the class: solid is
observed, dashed is correlated, dotted is hypothesized.*

---

## Why this exists

Every tracking pixel is a small admission. It tells you that a company bought
email analytics, that a provider is relaying its mail, that its links are
rewritten through a click tracker. None of that is visible in your inbox. All of
it is visible in the message headers and the HTML, if someone bothers to look
and then shows their work.

Most tools stop at "3 trackers blocked". PHANTOM answers the harder questions:

- **Who** is behind this message, underneath the display name?
- **What** infrastructure connects organisations that have no obvious relationship?
- **How sure** are we, and what exactly is the evidence?
- **What stopped appearing**, and what does that absence mean (and not mean)?
- **What is PHANTOM itself** doing to you while it audits everyone else?

---

## The five ideas

| # | Idea | Where it lives |
| --- | --- | --- |
| 1 | **Shadow ecosystem** — track the trackers, not just detect them | `backend/phantom/collector/`, `engine/` |
| 2 | **Phantom graphs** — three edge classes, evidence on every edge | `engine/classify.py`, `engine/relationship_engine.py` |
| 3 | **Metadata-first Gmail** — headers before bodies, two explicit tiers | `collector/gmail.py` |
| 4 | **Local exposure analysis** — contacts never leave the machine | `exposure/local_contacts.py` |
| 5 | **Negative space + self-audit** — record absence, audit yourself | `watchdog/`, `selfaudit/` |
| 6 | **Counter-observation** — make an extraction attempt reveal itself | `mirror/` |

### 1. The shadow ecosystem

Given one authorised message, PHANTOM extracts its relay chain, DKIM identity,
authentication results, routing headers, embedded pixels and click-redirect
wrappers, then resolves each domain against a small, reviewable registry. What
comes out is a graph of organisations, domains, mail hosts and providers.

### 2. Phantom graphs

A relationship graph shows what is known. A *phantom* graph also shows what is
possible and what is missing:

| Classification | Meaning | Confidence ceiling |
| --- | --- | --- |
| `observed` | Directly detected in a message you authorised | 0.99 |
| `correlated` | Recurring technical overlap across independent messages | 0.85 |
| `hypothesized` | A pattern that requires verification | 0.65 |

A hypothesized edge can never be promoted by volume alone. Every edge above
`observed` carries a standing caveat that the API and the UI are required to
display: shared infrastructure does not establish common ownership,
coordination, or data exchange.

### 3. Gmail integration, honestly

The convenient claim is "read-only Gmail". The honest version is that pixels
live in the body, so a metadata scope cannot see them. PHANTOM ships two tiers
and says so in the UI:

- **Metadata tier** (default, `gmail.metadata`): headers, labels, auth results.
  Sender infrastructure and relay chains, no pixels.
- **Body tier** (explicit opt-in, `gmail.readonly`): adds HTML so pixels and
  redirect wrappers become visible. The body is parsed in memory and discarded;
  only the URL, the reason it was flagged, and a hash survive.

PHANTOM never requests `gmail.send` or `gmail.modify`. It cannot send, label or
delete your mail. See [`docs/gmail-scopes.md`](docs/gmail-scopes.md).

### 4. Contact exposure without a social graph

The interesting question is where your digital exposure overlaps with the
organisations you already deal with. The dangerous implementation is uploading an
address book and building a relationship database out of other people's data.

PHANTOM does the narrow thing instead: you point it at a CSV **you** exported, it
discards names, raw addresses and phone numbers immediately, keeps only domains,
and tells you which of those domains also appear in your observed tracking
infrastructure. Opt-out by domain or by category. Nothing leaves the machine.

It also keeps four relationship kinds strictly separate, because they are not
interchangeable: `contact_record`, `technical_relationship`,
`communication_relationship`, `speculative_association`.

### 5. Negative space, and who watches the watchers

**Negative space** records what stops being observable: a pixel that disappears,
a redirect chain that shortens, infrastructure that changes. Every such event is
stored with `cause_unknown = true`, because a tracker going quiet is not proof
that tracking stopped. It might simply have moved somewhere you cannot see.

**Self-audit** is the part that keeps PHANTOM honest. All outbound traffic goes
through one chokepoint (`phantom/egress.py`) that checks an explicit allowlist
and logs every attempt, blocked ones included. `phantom selfaudit` scans the
source for code that bypasses it, lists which dependencies can open sockets, and
reports what actually left the machine.

```console
$ phantom selfaudit
Declared outbound hosts: oauth2.googleapis.com, gmail.googleapis.com, accounts.google.com
Unmediated network paths found: 0
Verdict: No unmediated outbound code paths found.
```

### 6. Counter-observation

A tracker blocker hides the tracker. PHANTOM also offers a way to learn about the
collector. Canary tokens are decoy images with an opaque token unique to one copy of
one document. When the document is extracted, the canary is fetched, and that request
volunteers its own network origin, client stack and timing.

```console
$ phantom mirror-demo
simulated 7 canary fetches across 5 origins
  leaked: pitch-deck v3 / acme        hits=3 clients=['browser-chromium', 'scripted']
  leaked: financial-model v2 / acme   hits=2 clients=['scripted']
  leaked: strategy-memo / northwind   hits=2 clients=['scripted']

7 canary fetch(es) from 5 origin(s) using 3 client stack(s) across 3 known network(s).
campaign clusters: 1 (hypothesized)
guardrails: retaliation=False raw_ip_retained=False
```

Those hits become a second graph, built by the same engine with the same three
classes and the same provenance rule: origins, client stacks and networks, joined by
`accessed_canary`, `shares_origin_infrastructure_with` and `campaign_cluster_with`.

**The line, stated up front:** this is passive. PHANTOM serves the image, writes a
row, and does nothing else. `RETALIATION_ENABLED = False` is hard-coded, not a
setting, because hacking back is illegal, attacks whoever owns the host actually
making the request, and would make this tool the surveillance layer it exists to
reveal. The graph holds canaries, origins, client stacks and networks. There is no
person at any node, and a test asserts that too. See
[`docs/counter-observation.md`](docs/counter-observation.md).

---

## Quickstart

```bash
git clone <your-fork> && cd phantom
python -m venv .venv && source .venv/bin/activate
pip install -e "backend[dev]"

# Run the whole pipeline over the synthetic sample corpus.
phantom demo          # email graph, negative space, self-audit
phantom mirror-demo   # counter-observation graph
```

`phantom demo` ingests `samples/*.eml`, builds the graph, runs the negative-space
scan and the self-audit, and writes:

```
out/report.md            human-readable findings
out/graph.json           Cytoscape elements, with provenance counts
out/negative-space.json  recorded changes in observability
out/selfaudit.json       PHANTOM's own footprint
```

Sample output, abridged:

```
ingested 6 messages
  acme-store.com         pixels=1 redirectors=1 dmarc=pass providers=Mailchimp
  northwind-supply.com   pixels=1 redirectors=1 dmarc=pass providers=Mailchimp
  acme-store.com         pixels=0 redirectors=0 dmarc=pass providers=-
  acme-supply.co         pixels=1 redirectors=0 dmarc=pass providers=Mailtrack

graph: 20 nodes, 17 edges {'observed': 15, 'correlated': 1, 'hypothesized': 1}
negative space: 6 observation(s) of change
self-audit: No unmediated outbound code paths found.
```

### Other commands

```bash
phantom ingest path/to/message.eml   # fold one message into the local graph
phantom graph                       # print Cytoscape JSON
phantom exposure contacts.csv       # local contact exposure check
phantom enroll --gmail you@gmail.com --consent-gmail
phantom selfaudit                   # audit PHANTOM's own network footprint
```

### API and UI

```bash
uvicorn phantom.main:app --reload --app-dir backend   # http://127.0.0.1:8000/docs
cd frontend && npm install && npm run dev             # http://localhost:5173
```

---

## Architecture

Six components, deliberately separable so the risky parts can be omitted:

| Component | Responsibility | Code |
| --- | --- | --- |
| **Phantom Collector** | Authorised ingestion, headers and URL extraction | `collector/` |
| **Tracker Registry** | Domain and provider identification, with sources | `registry/` |
| **Relationship Engine** | Evidence-backed graph construction | `engine/` |
| **Phantom Graph** | Uncertainty and relationship visualisation | `engine/graph.py`, `frontend/` |
| **Exposure Analyzer** | Local-only contact intersection analysis | `exposure/` |
| **Temporal Watchdog** | Historical change and negative space | `watchdog/` |
| **Counter-observation** | Canaries, attempt fingerprinting, counter-graph | `mirror/` |

Plus one that is not on the original list and should be:
**Self-audit** (`selfaudit/`), which keeps the other six accountable.

```
backend/phantom/
├── collector/      header + HTML parsing, Gmail two-tier client
├── registry/       curated tracker data (YAML, reviewable in a diff)
├── engine/         rules, classification, graph assembly
├── exposure/       local contact intersection analysis
├── watchdog/       negative space
├── selfaudit/      egress allowlist, scanner, own-footprint report
├── mirror/         canary tokens, attempt fingerprinting, counter-graph
├── auth/           Gmail OAuth + per-field revocable consent
├── api/            FastAPI surface
├── egress.py       the single outbound chokepoint
└── crypto.py       local key, encryption at rest
```

Stack: Python 3.11, FastAPI, SQLAlchemy (SQLite by default, PostgreSQL if you
configure it), NetworkX, React + Vite + Cytoscape.js, Docker.

---

## Security posture

- **Least privilege OAuth.** Metadata scope by default; body scope only on
  explicit opt-in; never `send` or `modify`.
- **No sending, ever.** No route in the API can send mail or a text message.
- **No contact uploads.** Contact analysis runs locally on a file you exported.
- **Fail closed.** Unlisted hosts raise `EgressBlocked` before a byte leaves;
  malformed data is refused rather than guessed at.
- **Provenance required.** The engine will not write an edge without at least one
  evidence row. A test asserts it.
- **Encryption at rest** for the little personal data PHANTOM holds, against a key
  that exists only on your machine.
- **Deletion is a feature.** Consent is per-field, revocable, and cleared
  immediately on revocation.

See [`SECURITY.md`](SECURITY.md) and [`docs/threat-model.md`](docs/threat-model.md).

---

## Documentation

| Document | Contents |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | Components, data flow, storage schema |
| [`docs/edge-provenance.md`](docs/edge-provenance.md) | Every rule, its caveat, and the confidence maths |
| [`docs/negative-space.md`](docs/negative-space.md) | What absence analysis may and may not claim |
| [`docs/gmail-scopes.md`](docs/gmail-scopes.md) | The two tiers and their limits |
| [`docs/privacy-model.md`](docs/privacy-model.md) | What is stored, what is not, retention, deletion |
| [`docs/threat-model.md`](docs/threat-model.md) | Adversaries, including PHANTOM itself |
| [`docs/ethics.md`](docs/ethics.md) | The line between privacy tools and people-tracking |
| [`docs/consent.md`](docs/consent.md) | The consent flow, field by field |
| [`docs/counter-observation.md`](docs/counter-observation.md) | Canaries, the asymmetry, and the passive-only line |
| [`docs/roadmap.md`](docs/roadmap.md) | What is built, what is next |

---

## What this is not

- Not a service. It runs on your machine, against your data.
- Not a people-finder. Contact analysis yields domains, never relationships
  between people.
- Not a verdict. It reports infrastructure and evidence. It does not tell you
  that two companies are secretly the same company.
- Not an offensive tool. The canary endpoint writes a row and returns a pixel.
  Nothing is sent back to the requester, and no code path could do so.
- Not finished. See the roadmap; the honest status is "working MVP, single data
  source, small registry".

## License

AGPL-3.0. If you run a modified PHANTOM as a network service, its users are
entitled to the source. A privacy tool that hides its own workings is a
contradiction.

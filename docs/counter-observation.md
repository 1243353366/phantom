# Counter-observation

*Turning an extraction attempt into intelligence about the attempt.*

## The idea in one paragraph

A canary is a decoy image with an unguessable token that is unique to one copy of
one document. If the document is collected, the canary is fetched, and the fetch
is a message you receive: it arrives with a network origin, a client stack, a
timestamp and a pattern of repeat visits. The asymmetry is the point. A collector
that touched the decoy learned that a URL resolved. You learned which of your
documents was extracted, by what, from where, and whether it was alone.

## What this is not

Not hacking back. PHANTOM's response to a canary fetch is to serve the image and
write a row. That is the entire response, and it is a hard architectural
constraint, not a policy:

```python
# phantom/mirror/__init__.py
RETALIATION_ENABLED = False   # hard-coded, not a setting
```

Three reasons this line does not move:

1. **It is illegal.** The CFAA in the US, the Computer Misuse Act in the UK, and
   equivalent statutes across the EU criminalise unauthorised access to a system,
   regardless of whether that system was used to attack you.
2. **It hits the wrong target.** The address making the request is frequently a
   compromised host, a cloud function, or an open proxy. Retaliation attacks a
   bystander.
3. **It defeats the purpose.** A privacy tool that quietly acquires an offensive
   capability is a surveillance layer with good branding. See `docs/ethics.md`.

The tests assert all three: `test_guardrails_are_reported_and_retaliation_is_impossible`
and `test_beacon_never_makes_an_outbound_request`.

## The mechanism

```
document ──▶ canary URL (opaque token)
                    │
        someone fetches it
                    ▼
        ┌──────────────────────────┐
        │ beacon  (/mirror/b/…)    │
        │  · serve 1x1 GIF         │
        │  · record what arrived   │
        │  · bounded tarpit (opt-in)│
        └────────────┬─────────────┘
                     ▼
   origin (HMAC) · client stack · local-ASN · signals · timing
                     │
                     ▼
         counter-infrastructure graph
```

### Tokens

`phantom.mirror.tokens.mint()` creates a 16-byte URL-safe token, signs it with the
local key, and stores the mapping to a label. The label is never encoded in the URL,
so an attacker who sees the URL learns nothing about which document they hold.
That single design choice is what turns "something was fetched" into
"this specific copy was extracted".

Verification collapses every failure into `None`: a revoked token, a malformed one
and a forged signature are indistinguishable to a prober. The endpoint still returns
a valid GIF in all three cases, because a 404 would tell them they had been detected.

### Fingerprinting, deliberately narrow

Only headers the client chose to send are kept, from a fixed allowlist
(`mirror/fingerprint.py:KEPT_HEADERS`). No cookies are set. There is no JavaScript
challenge, no canvas probe and no TLS-fingerprint harvesting, because those cross from
"observing what was offered" into interrogating the visitor.

Client grouping is by **tool**, not by version string, so `python-requests/2.31`
and `python-requests/2.32` are one cluster, while `python-requests` and `Scrapy` are
two. A scraper that upgrades itself does not become a new actor; two different tools
do not collapse into one.

Network attribution uses a **local ASN table only** (`PHANTOM_HOME/asn.csv`,
format `prefix,asn,organisation`). PHANTOM never calls an IP-intelligence API,
because handing a canary hit to a third party leaks precisely the information the
canary exists to keep.

### The bounded tarpit

Off by default. When enabled, an automated-looking client is held for a delay
proportional to its signal weight, hard-capped at 2000 ms in code regardless of
configuration. A browser is never held.

The cap exists because an unbounded tarpit turns the honeypot into a
resource-exhaustion weapon against the person running it. A canary must never be
able to hurt its own operator.

## The graph

`mirror/countergraph.py` folds every hit into the same node/edge/evidence model as
the email graph, through the same writer, so the provenance invariant holds in both.

| Node kind | Meaning | Contains |
| --- | --- | --- |
| `canary` | A placed decoy | The label you gave it |
| `origin` | A source address | HMAC by default, never a raw IP unless opted in |
| `client` | A client stack | Family plus tool name, never a person |
| `asn` | A network | From your local table |

| Rule | Relation | Class | Trigger |
| --- | --- | --- | --- |
| `R-MIR-1` | `accessed_canary` | observed | A request arrived at this canary |
| `R-MIR-2` | `presented_client` | observed | This origin sent this client stack |
| `R-MIR-3` | `originates_from` | observed | Origin resolved to a network in the local table |
| `R-MIR-4` | `shares_origin_infrastructure_with` | correlated | Distinct origins, same client stack, same network |
| `R-MIR-5` | `campaign_cluster_with` | hypothesized | Two canaries touched by the same client stack |

`R-MIR-5` is capped at 0.65 confidence and carries a caveat in the response:
common tooling is not proof of a common operator, and a widely used crawler will
cluster everything it touches.

### There is no person in this graph

Node kinds are restricted to `canary`, `origin`, `client`, `asn`, and a test
asserts it. There is no name, account or identifier of an individual at any node,
because PHANTOM does not collect what would be needed to draw one. What the graph
maps is infrastructure: whose tooling touched your decoys, from which networks,
in what groupings.

Note what a "social graph of the attacker" would actually require: identities,
accounts, associations between people. Building that would need exactly the
capability this project exists to refuse. What is here is the useful subset that
does not require it.

## Bursts are not corroboration

Repeat fetches by the same client from the same origin within an hour
(`BURST_WINDOW_MIN`) collapse into one episode. Without that, one eager scanner
would look like a well-corroborated campaign. The same discipline as the email
side: one event is one observation, however many times it repeats.

## Reading the report

`phantom mirror-report` (or the Counter-observation tab) returns both halves of
the asymmetry explicitly:

```
what_they_learned:   That a URL resolved and returned an image. Nothing about you.
                     Nothing about which document the canary sat in.
what_you_learned:    Which N of your copies were extracted, by label.
                     The network origin of each fetch.
                     The client stack, and the signals behind that conclusion.
                     Timing and burst structure.
                     Which canaries cluster into a likely campaign.
```

## Caveats that ship with every report

- An access is not an identity. Anyone can send a request with any user agent.
- A shared network is not a shared actor: cloud regions and proxy pools host
  unrelated traffic.
- Behind a proxy chain the observed origin is the proxy, not the requester.
- If the canary is published publicly, a search-engine crawler will fetch it, and
  that is not an attack.

## Retention

Canary hits are the most sensitive rows PHANTOM holds, so they expire on their own
schedule: `mirror_retention_days`, default 30, enforced by
`beacon.purge_expired()` and exposed at `POST /api/mirror/purge`. Raw source
addresses are not stored at all unless `PHANTOM_RETAIN_RAW_IP=1`.

## Try it

```bash
phantom mirror-demo            # simulate seven fetches across five origins
phantom mirror-report          # JSON report
phantom canary --label "pitch-deck v3 / acme"   # mint one to place in a document
```

The demo uses the real recording path, so what you see is what real traffic
produces. It writes `out/counter-report.json` and `out/counter-graph.json`.

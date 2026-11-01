# ShadowTrace (Layer 3)

*Recording what tried to reach what you protect, without ever reaching back.*

## Three layers, one graph, no merges

| Layer | Question it answers | Node kinds |
| --- | --- | --- |
| 1 · Surveillance | Who is positioned to observe you? | `organization`, `provider`, `domain`, `mail_host`, `dkim_identity` |
| 2 · Relationship | Who do you actually talk to? | contact domains, processed locally, never uploaded |
| 3 · Adversarial | What interacted with your protective infrastructure? | `decoy`, `protected_object`, `payload`, `origin`, `client`, `asn` |

Layers 1 and 2 are joined by ordinary evidence: a message you authorised shows
both. Layer 3 is different in kind. It observes *your* infrastructure, not someone
else's, and the thing it observes is an attempt rather than a fact about a
relationship.

So the layers stay in separate node namespaces, and the join is a decision rather
than a computed edge. See [`identity-separation.md`](identity-separation.md) for why
that is enforced in code.

## What gets recorded

Four event kinds. Each is an observation with a content-addressed fingerprint, an
entry in the [evidence vault](evidence-vault.md), and at least one innocent
explanation attached.

| Kind | Recorded when | Outcome values |
| --- | --- | --- |
| `decoy_access` | something fetched a canary or decoy | `observed` |
| `protected_data_request` | something asked MirrorLock to decrypt | `granted`, `denied` |
| `payload_quarantined` | a suspicious payload was captured | `quarantined` |
| `integrity_check` | the vault or a blob was verified | `observed` |

Every event stores: kind, outcome, the protected object touched, the observable
infrastructure (hashed origin, client stack, network from the local table), a
detail line, and the alternative explanations.

It does not store: a name, an account, an email address, a raw IP by default, the
plaintext of anything protected, or any credential material that arrives in a
request. A request carrying `password=…` is recorded with the secret replaced by
`[redacted: credential material refused]` and flagged, and the tests assert the
secret never reaches the database.

## Rules

Layer 3 writes four rules of its own, and reuses the counter-observation rules
where the observation is identical.

| Rule | Relation | Class | Trigger |
| --- | --- | --- | --- |
| `R-SHD-1` | `requested_protected_object` | observed | One event reached this object from this origin |
| `R-SHD-2` | `recurring_origin_with` | correlated | One origin reached more than one protected object |
| `R-SHD-3` | `co_occurs_with` | hypothesized | Two objects reached inside one time window by one indicator |
| `R-SHD-4` | `same_infrastructure_as` | hypothesized | A human confirmed a bridge proposal |

`R-MIR-2` (`presented_client`) and `R-MIR-3` (`originates_from`) are reused, so a
canary hit and a refused decryption request from the same origin land on the same
node. That sharing is the point: it is what makes the joined view useful without
merging any identities.

## The refusal log

A refused request is the most informative event in the layer and the easiest one to
lose. MirrorLock therefore records every request, granted or denied, before it
returns anything.

The report says this out loud, because the alternative reading is an accusation:

> N request(s) for protected data were recorded and refused, and a refusal is not
> an accusation: an expired grant and a hostile probe produce the same row.

Default is denial. A read succeeds only while a live, unrevoked grant exists, and a
grant is capped at 24 hours. There is no code path where a caller supplies its own
authorisation.

## Temporal proximity

Two protected objects reached by one indicator inside a window is worth knowing. It
is also what a directory crawler, a mailbox scanner or a backup job produces all day.
So `R-SHD-3` starts at 0.35 confidence, is capped by the hypothesis ceiling at 0.65,
and arrives with three to five innocent readings.

## Reading it honestly

The report closes with what the layer cannot tell you, and that list is not
decoration:

- Who any observable belongs to. There is no identity at any node.
- Whether an attempt was hostile. Intent is not observable here.
- Whether two events share an operator, as opposed to a network or a tool.
- Anything about a third party's systems. Layer 3 only records what arrived at yours.

## Try it

```console
$ phantom shadow-demo
layer 3 events: 8  {'decoy_access': 4, 'protected_data_request': 3, 'payload_quarantined': 1}
outcomes: {'observed': 4, 'denied': 2, 'granted': 1, 'quarantined': 1}
  touched: decoy:pitch-deck v3              events=2 ['observed']
  touched: decoy:strategy-memo              events=2 ['observed']
  touched: vault:fe435ee2…                  events=2 ['denied']
  touched: vault:b33734c9…                  events=1 ['granted']
  touched: payload:bbe38aaf…                events=1 ['quarantined']

recurring indicators: 4
co-occurrence candidates: 3 (hypothesized, capped)
quarantined payloads: 1 (executed: False)
vault: intact (8 records)
automatic layer merges: 0
bridges pending: 0 confirmed: 0

$ phantom vault-verify
{ "ok": true, "checked": 8, "reason": "every record reseals to its stored seal and links to its predecessor" }
```

## Endpoints

```
GET  /api/shadow/events          recorded observations
GET  /api/shadow/indicators      recurrence and temporal proximity
GET  /api/shadow/report          the full Layer 3 report
GET  /api/shadow/graph           Layer 3 view; ?include_surveillance=true adds confirmed bridges
GET  /api/shadow/vault           recompute the hash chain
GET  /api/shadow/bridges         proposals and decisions
POST /api/shadow/bridges         propose a join (never automatic)
POST /api/shadow/bridges/{id}/confirm
POST /api/shadow/bridges/{id}/reject
POST /api/shadow/mirrorlock      lock a protected object
POST /api/shadow/mirrorlock/{id}/request     recorded, denied by default
POST /api/shadow/mirrorlock/{id}/grant       the only way a read can succeed
POST /api/shadow/quarantine      store a suspicious payload encrypted, unopened
```

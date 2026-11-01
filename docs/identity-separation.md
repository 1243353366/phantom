# Identity separation

*The rule that has to survive every future contributor.*

## The rule

A surveillance-layer entity and an adversarial-layer entity are **different nodes**.
Nothing in the system may make them one node, infer that they are the same entity,
or treat a shared observable as evidence of shared identity.

The layers join in exactly one way: a human writes a proposal naming a shared
observable, reviews it, and confirms it. That produces one edge, classified
`hypothesized`, capped at 0.65 confidence, carrying a caveat that lists the innocent
explanations.

## Why this is code and not policy

A promise in a README survives approximately one refactor. The rule is therefore
enforced at the only place that can create an edge:

```python
# phantom/engine/relationship_engine.py
rule = classify.RULES[rule_id]
if rule.requires_confirmation and not confirmed:
    raise classify.UnconfirmedCrossLayerEdge(
        f"{rule_id} joins the surveillance and adversarial layers and "
        "cannot be written by ingestion"
    )
```

`R-SHD-4` is the only rule that sets `requires_confirmation=True`. Ingestion never
passes `confirmed=True`; only `phantom.shadow.bridges.confirm()` does, after a
proposal exists in the database with a recorded decision.

Tests that fail if this is weakened:

- `test_engine_refuses_a_cross_layer_edge_from_ingestion`
- `test_projection_creates_no_cross_layer_edge`
- `test_adversarial_projection_stays_out_of_the_surveillance_namespace`
- `test_bridge_requires_a_rationale_naming_the_observable`
- `test_bridge_refuses_two_entities_from_the_same_layer`
- `test_rejecting_a_bridge_creates_no_edge_and_blocks_confirmation`

There is also a deliberate refusal in `phantom/shadow/__init__.py`:

```python
class IdentityMergeRefused(RuntimeError):
    """PHANTOM will not collapse a person, an organisation and an address into one node."""
```

It is never raised, because the code that would raise it does not exist. It is there
so the intent is visible to whoever notices that a `merge_nodes()` helper would tidy
things up.

## The four confusions this prevents

| Tempting inference | What is actually true |
| --- | --- |
| "The tracker and the org are the same because they share a CDN" | CDNs serve millions of unrelated parties |
| "The scraper is the sender because it fetched the email's pixel" | Mail-security scanners and prefetchers fetch everything |
| "The refused request came from the same operator as the canary hit" | A shared network is a shared network, often a corporate NAT or cloud region |
| "This contact is involved because their domain overlaps with a tracker" | A contact relationship is not a technical relationship |

Each one is a plausible story that the data does not support, and each is exactly
the story a person under pressure will reach for.

## What the joined view is allowed to say

After a confirmed bridge, the graph may state:

> On the evidence recorded here, this adversarial-layer origin and this
> surveillance-layer entity appear to share an observable. That is the whole claim.

It may not state that they are the same actor, that one works for the other, or that
the shared observable means anything about intent. The caveat says so, and the
confidence ceiling says so, and if a consumer strips both, that is a failure of the
consumer.

## Layer 2 is deliberately thinner

Contact analysis never enters the graph as an edge. It produces a local
intersection report (`POST /api/exposure/scan`) that exists only in the response to a
request you made. Uploading a contact list to build relationships with them would be
the one design decision that turns this project into the thing it maps, so it is
absent rather than disabled.

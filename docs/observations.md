# Raw observations and derived claims

*So that a change to the algorithm does not quietly rewrite history.*

## The split

| | Raw observation | Derived claim |
| --- | --- | --- |
| Table | `raw_observations` | `nodes`, `edges`, `evidence` |
| Written by | `RelationshipEngine.ingest()` | `RelationshipEngine.project()` and `correlate()` |
| Mutability | append-only | disposable, rebuilt at will |
| Contains | headers, hosts, URLs, reasons, timestamps | relationships, classifications, confidences, caveats |
| Body content | never | n/a |

Before this split, the graph was the only record. A rule change then left the
database holding conclusions from a rule that no longer existed, and the only way
back was to re-read the original messages. Layer 3 already worked the other way
round: a sealed event is the raw record, and `shadow/graph.py` derives edges from
it. The mail path now matches.

## Why it is enforced rather than assumed

`observations.store()` refuses any payload containing a key outside
:data:`phantom.observations.PAYLOAD_KEYS`:

```python
unknown = set(payload) - PAYLOAD_KEYS
if unknown:
    raise ValueError(
        f"refusing to store unexpected observation fields: {sorted(unknown)}. "
        "Adding a field means reviewing whether it can carry message content."
    )
```

A future change that wants to store a body, a rendered snippet, a subject line or
a recipient list has to edit that list, in a diff someone reviews. `subject_hash`
exists precisely so the text never needs to. Tests:
`test_payload_is_metadata_only`, `test_message_body_text_never_reaches_the_observation`,
`test_an_unexpected_field_is_refused`.

## Rebuilding

```console
$ phantom rebuild-graph
observations replayed: 6
nodes    20 -> 20
edges    19 -> 19
evidence rows      30
bridges restored:  0
rules digest:      12ca5c06a5688c30
graph reproduced:  yes, byte-identical claim set
```

Rebuild deletes `nodes`, `edges` and `evidence`, replays every stored observation
through the current rules, and compares a digest of the claim set before and after.
The digest covers source, target, relation, classification, **confidence and
caveat**: leaving the last two out would let a rule change look like a no-op.

Anything not derived is left alone: raw observations, sealed Layer 3 events, the
evidence vault, consent records, grants, quarantined payloads.

### A confirmed bridge is a decision, not a derivation

`bridges.reapply()` restores the edge for every proposal already marked
`confirmed`, using the rationale, the deciding party and the note already on the
record. It does not re-ask and it does not invent. A proposal whose surveillance
endpoint no longer exists is reported as skipped rather than resurrected.

Rejected proposals stay rejected. A rebuild never produces a cross-layer edge that
a human did not confirm: `test_rebuild_gives_no_one_a_way_to_launder_a_bridge`.

## Two derivation passes, found by building this

The first rebuild lost two edges out of nineteen. The cause was not the
observations: correlation (`R-COR-1`, `R-HYP-*`) is a **global** pass over the whole
graph, not a per-observation one, so a replay that only calls `project()` silently
drops every correlated and hypothesized edge.

That is the value of the exercise. The rebuild is now the pipeline, in order:

1. replay each observation through `project()`
2. run `correlate()` once over the result
3. project Layer 3 events
4. reapply confirmed bridges

If a fifth step is ever added, it has to be added here too, or `reproduced` will
say `no` and the divergence becomes visible instead of silent.

## What this does and does not give you

It gives you: the ability to change a threshold, a caveat or a correlation window
and re-derive every claim honestly; a visible difference when a rule change alters
the graph; and a raw record that outlives the rules.

It does not give you: protection against a wrong observation. If the parser
misread a header, the observation is wrong and every rebuild will be consistently
wrong in the same direction. The array of pixels and reasons stored alongside each
observation is what lets someone check that by hand.

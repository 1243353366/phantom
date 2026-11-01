"""Rebuild the graph from stored observations.

The point of the raw/derived split is that this is possible. When a rule, a
threshold or a caveat changes, the honest move is to re-derive every claim from
what was actually observed rather than leave the old conclusions in place with a
new version number on them.

What is rebuilt: nodes, edges, evidence. All of it is derived.
What is not touched: raw observations, sealed Layer 3 events, the evidence vault,
consent records, grants, quarantined payloads, and recorded bridge decisions.

A confirmed bridge is a decision, not a derivation, so it is restored as it was
rather than recomputed.
"""
from __future__ import annotations

import hashlib
import json

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from phantom import observations
from phantom.engine import classify
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.mirror import countergraph
from phantom.models import Edge, Evidence, Node
from phantom.shadow import bridges
from phantom.shadow import graph as shadow_graph


def rules_digest() -> str:
    """Fingerprint of the claim-making logic, so a rebuild can be attributed."""
    material = json.dumps(
        sorted(
            (r.id, r.classification, r.relation, r.caveat or "", r.requires_confirmation)
            for r in classify.RULES.values()
        ),
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def counts(session: Session) -> dict:
    return {
        "nodes": len(session.scalars(select(Node)).all()),
        "edges": len(session.scalars(select(Edge)).all()),
        "evidence": len(session.scalars(select(Evidence)).all()),
    }


def graph_digest(session: Session) -> str:
    """Order-independent fingerprint of every claim currently in the graph."""
    # Confidence and caveat are part of the claim. Leaving them out would make a
    # rebuild look identical after a rule change had quietly altered both.
    rows = sorted(
        (edge.src_key, edge.dst_key, edge.relation, edge.classification,
         round(edge.confidence, 4), edge.caveat or "")
        for edge in session.scalars(select(Edge))
    )
    material = json.dumps(rows, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def rebuild(session: Session) -> dict:
    """Drop every derived row and re-derive it from what was observed."""
    before = counts(session)
    before_digest = graph_digest(session)
    rules_before = rules_digest()

    session.execute(delete(Evidence))
    session.execute(delete(Edge))
    session.execute(delete(Node))
    session.commit()

    engine = RelationshipEngine(session)
    stored = observations.load(session, source_kind=observations.EMAIL_METADATA)
    for row in stored:
        engine.project(
            observations.from_payload(row.payload), source_ref=row.source_ref
        )
    session.commit()

    # Correlation is a second derivation pass over the whole graph, not a
    # per-observation one. Rebuilding without it silently loses every
    # correlated and hypothesized edge, which is how this omission was found.
    correlated = engine.correlate()
    session.commit()

    # Four derivation sources, in order, and the list is the pipeline. Two of them
    # were found to be missing by running this, not by reading it: the correlation
    # pass and the counter-observation projection.
    mirror = countergraph.build(session)
    session.commit()

    shadow = shadow_graph.project(session)
    restored = bridges.reapply(session)

    after = counts(session)
    after_digest = graph_digest(session)

    return {
        "observations_replayed": len(stored),
        "correlation_passes": correlated,
        "counter_edges": mirror.get("edges", 0),
        "layer3_edges": shadow.get("recurrence_edges", 0) + shadow.get("co_occurrence_edges", 0),
        "bridges_restored": restored,
        "rules_digest": rules_before,
        "before": before,
        "after": after,
        "graph_digest": {"before": before_digest, "after": after_digest},
        "reproduced": before_digest == after_digest,
        "note": (
            "A confirmed bridge is a recorded human decision, so it is restored "
            "rather than recomputed. Everything else here is derived."
        ),
    }

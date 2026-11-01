"""Graph assembly and export.

NetworkX does the analysis, Cytoscape renders it. Nothing here invents an edge;
it only shapes what the engine already proved.
"""
from __future__ import annotations

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.models import Edge, Node
from phantom.shadow import layer_of


def build_graph(session: Session) -> nx.DiGraph:
    g = nx.DiGraph()
    for node in session.scalars(select(Node)):
        g.add_node(
            node.key,
            label=node.label,
            kind=node.kind,
            attrs=node.attrs,
            layer=layer_of(node.kind),
            first_seen=node.first_seen.isoformat(),
            last_seen=node.last_seen.isoformat(),
        )
    for edge in session.scalars(select(Edge)):
        if not g.has_node(edge.src_key) or not g.has_node(edge.dst_key):
            continue
        g.add_edge(
            edge.src_key,
            edge.dst_key,
            id=edge.id,
            relation=edge.relation,
            classification=edge.classification,
            rule_id=edge.rule_id,
            confidence=edge.confidence,
            observation_count=edge.observation_count,
            caveat=edge.caveat,
            evidence_count=len(edge.evidence),
        )
    return g


def to_cytoscape(session: Session) -> dict:
    """Cytoscape.js elements plus the caveats the UI must surface."""
    g = build_graph(session)
    elements = []

    centrality = {k: 0.0 for k in g.nodes}
    undirected = g.to_undirected()
    if undirected.number_of_nodes() > 2:
        try:
            centrality = nx.betweenness_centrality(undirected)
        except Exception:
            centrality = {k: 0.0 for k in g.nodes}

    for key, data in g.nodes(data=True):
        elements.append(
            {
                "data": {
                    "id": key,
                    "label": data.get("label", key),
                    "kind": data.get("kind"),
                    "layer": data.get("layer", layer_of(data.get("kind", ""))),
                    "centrality": round(centrality.get(key, 0.0), 4),
                    "degree": g.degree(key),
                    **{
                        k: v
                        for k, v in data.get("attrs", {}).items()
                        if k in ("category", "parent", "role", "domain")
                    },
                    # "source" would collide with Cytoscape's edge source field.
                    "registry_source": data.get("attrs", {}).get("source"),
                }
            }
        )

    for src, dst, data in g.edges(data=True):
        elements.append(
            {
                "data": {
                    "id": data["id"],
                    "source": src,
                    "target": dst,
                    "relation": data["relation"],
                    "classification": data["classification"],
                    "rule_id": data["rule_id"],
                    "confidence": data["confidence"],
                    "observations": data["observation_count"],
                    "evidence_count": data["evidence_count"],
                    "caveat": data.get("caveat"),
                }
            }
        )

    return {
        "elements": elements,
        "stats": summarize(g),
        "layers": {
            "surveillance": "Organisations, providers and tracking infrastructure.",
            "relationship": "Your contacts, processed locally and never uploaded.",
            "adversarial": "Observables that interacted with your decoys and locks.",
        },
        "legend": {
            "observed": "Directly detected in a message you authorised.",
            "correlated": "Recurring overlap across independent observations.",
            "hypothesized": "Suggested by a pattern. Not verified. Treat as a question.",
        },
        "caveats": sorted({d["caveat"] for *_, d in g.edges(data=True) if d.get("caveat")}),
    }


def summarize(g: nx.DiGraph) -> dict:
    by_class: dict[str, int] = {"observed": 0, "correlated": 0, "hypothesized": 0}
    for *_, d in g.edges(data=True):
        by_class[d["classification"]] = by_class.get(d["classification"], 0) + 1

    by_layer: dict[str, int] = {}
    for _, d in g.nodes(data=True):
        layer = d.get("layer") or layer_of(d.get("kind", ""))
        by_layer[layer] = by_layer.get(layer, 0) + 1

    by_kind: dict[str, int] = {}
    for _, d in g.nodes(data=True):
        by_kind[d["kind"]] = by_kind.get(d["kind"], 0) + 1

    if g.number_of_nodes() == 0:
        connectors: list[dict] = []
    else:
        connectors = [
            {"key": k, "label": g.nodes[k].get("label", k), "degree": deg}
            for k, deg in sorted(g.degree, key=lambda kv: kv[1], reverse=True)[:10]
            if deg > 0
        ]

    return {
        "nodes": g.number_of_nodes(),
        "edges": g.number_of_edges(),
        "edges_by_classification": by_class,
        "nodes_by_kind": by_kind,
        "nodes_by_layer": by_layer,
        "top_connectors": connectors,
        "density": round(nx.density(g), 4) if g.number_of_nodes() > 1 else 0.0,
    }


def explain_edge(session: Session, edge_id: str) -> dict:
    """Full provenance for one edge: the receipts behind the claim."""
    edge = session.get(Edge, edge_id)
    if edge is None:
        return {"error": "edge not found"}
    return {
        "id": edge.id,
        "from": edge.src_key,
        "to": edge.dst_key,
        "relation": edge.relation,
        "classification": edge.classification,
        "rule_id": edge.rule_id,
        "confidence": edge.confidence,
        "observations": edge.observation_count,
        "caveat": edge.caveat,
        "first_seen": edge.first_seen.isoformat(),
        "last_seen": edge.last_seen.isoformat(),
        "evidence": [
            {
                "kind": e.kind,
                "detail": e.detail,
                "source_ref": e.source_ref,
                "snippet_hash": e.snippet_hash,
                "observed_at": e.observed_at.isoformat(),
                "payload": e.payload,
            }
            for e in sorted(edge.evidence, key=lambda x: x.observed_at)
        ],
    }

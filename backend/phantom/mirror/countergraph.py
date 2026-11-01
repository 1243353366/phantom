"""The counter-infrastructure graph.

If the shadow ecosystem graph maps who touches your mail, this maps who touches
your decoys. It is the same three-class model pointed outward: an access is
observed, repeated overlap is correlated, a campaign grouping is hypothesized
and capped.

What it deliberately is not: a graph of people. Nodes are canaries, network
origins (pseudonymous), client stacks and autonomous systems. There is no name,
no account and no individual at any node, because PHANTOM never collects what
would be needed to draw one.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.engine.classify import RULES
from phantom.engine.graph import summarize
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.mirror import tokens
from phantom.mirror.models import CanaryToken, MirrorObservation

#: Two hits on the same client within this many minutes belong to one burst and
#: count as a single episode rather than independent corroboration.
BURST_WINDOW_MIN = 60


def _short(value: str, n: int = 12) -> str:
    return value[:n]


def build(session: Session) -> dict:
    """Fold every canary hit into the graph, then infer campaigns."""
    engine = RelationshipEngine(session)
    rows = session.execute(
        select(MirrorObservation, CanaryToken).join(
            CanaryToken, MirrorObservation.token_id == CanaryToken.id
        )
    ).all()

    by_client: dict[str, set[str]] = defaultdict(set)
    by_canary_client: dict[str, set[str]] = defaultdict(set)
    origins_by_client_asn: dict[tuple[str, int | None], set[str]] = defaultdict(set)

    for obs, canary in rows:
        canary_key = f"canary:{tokens.token_fingerprint(canary.token)}"
        origin_key = f"origin:{_short(obs.origin_hmac)}"
        client_key = f"client:{_short(obs.client_hash)}"

        engine.node(
            canary_key, "canary", canary.label,
            {"label": canary.label, "role": "decoy", "created_at": canary.created_at.isoformat()},
        )
        engine.node(
            origin_key, "origin", f"origin…{_short(obs.origin_hmac, 6)}",
            {"role": "network-origin", "pseudonymous": True,
             "raw_ip_retained": obs.origin_raw is not None},
        )
        engine.node(
            client_key, "client",
            f"{obs.client_family}"
            + (f" · {obs.client_tool}" if obs.client_tool else ""),
            {"family": obs.client_family, "tool": obs.client_tool,
             "signals": len(obs.extraction_signals)},
        )

        engine.edge(
            "R-MIR-1", origin_key, canary_key,
            evidence_kind="canary_access",
            detail=(
                f"{canary.label} fetched by a {obs.client_family} client"
                + (f" with {len(obs.extraction_signals)} automated-consumption signal(s)"
                   if obs.extraction_signals else "")
            ),
            source_ref=f"mir:{obs.id}:access",
            payload={
                "received_at": obs.received_at.isoformat(),
                "client_family": obs.client_family,
                "signals": obs.extraction_signals,
                "tarpit_ms": obs.tarpit_ms,
            },
            base_confidence=0.9,
            observed_at=obs.received_at,
        )
        engine.edge(
            "R-MIR-2", origin_key, client_key,
            evidence_kind="client_presented",
            detail=f"Origin presented client stack '{obs.client_family}'",
            source_ref=f"mir:{obs.id}:client",
            payload={"received_at": obs.received_at.isoformat()},
            base_confidence=0.8,
            observed_at=obs.received_at,
        )
        if obs.asn is not None:
            asn_key = f"asn:{obs.asn}"
            engine.node(
                asn_key, "asn", obs.asn_org or f"AS{obs.asn}",
                {"asn": obs.asn, "org": obs.asn_org, "source": "local asn table"},
            )
            engine.edge(
                "R-MIR-3", origin_key, asn_key,
                evidence_kind="asn_resolution",
                detail=f"Resolved to AS{obs.asn}"
                       + (f" ({obs.asn_org})" if obs.asn_org else "")
                       + " using the local ASN table",
                source_ref=f"mir:{obs.id}:asn",
                payload={"asn": obs.asn},
                base_confidence=0.7,
                observed_at=obs.received_at,
            )
            origins_by_client_asn[(obs.client_hash, obs.asn)].add(origin_key)

        by_client[obs.client_hash].add(origin_key)
        by_canary_client[canary_key].add(obs.client_hash)

    # --- correlated: one client stack across distinct origins ----------
    correlated = 0
    for (client_hash, asn), origins in origins_by_client_asn.items():
        if len(origins) < 2:
            continue
        client_key = f"client:{_short(client_hash)}"
        ordered = sorted(origins)
        for i, a in enumerate(ordered):
            for b in ordered[i + 1:]:
                engine.edge(
                    "R-MIR-4", a, b,
                    evidence_kind="shared_client_origin",
                    detail=(
                        f"Two origins presented the same {client_key.split(':')[1]} "
                        f"client stack on AS{asn}"
                    ),
                    source_ref=f"corr:{client_hash[:12]}:{asn}:{a}:{b}",
                    base_confidence=0.5,
                )
                correlated += 1

    # --- hypothesized: campaign clusters via a shared client ----------
    clusters = 0
    canaries_by_client: dict[str, set[str]] = defaultdict(set)
    for canary_key, clients in by_canary_client.items():
        for c in clients:
            canaries_by_client[c].add(canary_key)
    for client_hash, canaries in canaries_by_client.items():
        if len(canaries) < 2:
            continue
        ordered = sorted(canaries)
        for i, a in enumerate(ordered):
            for b in ordered[i + 1:]:
                engine.edge(
                    "R-MIR-5", a, b,
                    evidence_kind="shared_client_stack",
                    detail=(
                        f"Both canaries were fetched by the same "
                        f"'{_client_label(session, client_hash)}' client stack"
                    ),
                    source_ref=f"campaign:{client_hash[:12]}:{a}:{b}",
                    base_confidence=0.4,
                )
                clusters += 1

    session.commit()
    return {"correlated_edges": correlated, "campaign_clusters": clusters}


def _client_label(session: Session, client_hash: str) -> str:
    row = session.scalar(
        select(MirrorObservation.client_family)
        .where(MirrorObservation.client_hash == client_hash)
        .limit(1)
    )
    return row or "unknown"


MIRROR_KINDS = {"canary", "origin", "client", "asn"}


def to_cytoscape(session: Session) -> dict:
    """Export only the counter-observation subgraph, with the same caveats."""
    from phantom.engine.graph import build_graph

    full = build_graph(session)
    g = nx.DiGraph()
    for key, data in full.nodes(data=True):
        if data.get("kind") in MIRROR_KINDS:
            g.add_node(key, **data)

    for src, dst, data in full.edges(data=True):
        if g.has_node(src) and g.has_node(dst):
            g.add_edge(src, dst, **data)

    elements = []
    for key, data in g.nodes(data=True):
        elements.append(
            {
                "data": {
                    "id": key,
                    "label": data.get("label", key),
                    "kind": data.get("kind"),
                    "degree": g.degree(key),
                    **{k: v for k, v in data.get("attrs", {}).items()
                       if k in ("family", "tool", "org", "asn", "signals", "role")},
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
        "legend": {
            "observed": "A request that actually arrived at a canary.",
            "correlated": "The same client stack seen from distinct origins.",
            "hypothesized": "Canaries grouped by shared tooling. Verify before believing.",
        },
        "caveats": sorted({d["caveat"] for *_, d in g.edges(data=True) if d.get("caveat")}),
        "node_kinds": {
            "canary": "A placed decoy. Its label is the copy that leaked.",
            "origin": "A pseudonymous source address, HMAC only by default.",
            "client": "A client stack (user agent family), not a person.",
            "asn": "A network, from your local ASN table. No API call was made.",
        },
    }


def bursts(session: Session) -> list[dict]:
    """Group hits into episodes so repeat fetches are not read as corroboration."""
    rows = session.execute(
        select(MirrorObservation).order_by(MirrorObservation.received_at)
    ).scalars().all()
    episodes: list[dict] = []
    for obs in rows:
        if episodes:
            last = episodes[-1]
            same = (
                last["client_hash"] == obs.client_hash
                and last["origin_hmac"] == obs.origin_hmac
                and (obs.received_at - last["last_at"]) <= dt.timedelta(minutes=BURST_WINDOW_MIN)
            )
            if same:
                last["count"] += 1
                last["last_at"] = obs.received_at
                continue
        episodes.append(
            {
                "client_hash": obs.client_hash,
                "client_family": obs.client_family,
                "origin_hmac": obs.origin_hmac,
                "asn": obs.asn,
                "first_at": obs.received_at,
                "last_at": obs.received_at,
                "count": 1,
            }
        )
    return [
        {**e, "first_at": e["first_at"].isoformat(), "last_at": e["last_at"].isoformat()}
        for e in episodes
    ]

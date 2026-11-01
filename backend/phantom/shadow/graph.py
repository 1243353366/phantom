"""Projecting Layer 3 into the unified graph.

Same writer, same rules, same provenance requirement as the mail graph. The only
thing that is different is what the nodes mean: an address hash, a client stack
and a network, rather than an organisation and a domain.

Node keys are namespaced by layer so that a Layer 3 node can never collide with a
Layer 1 node. Where the two layers already share observable infrastructure, the
shared key is the point: a canary hit and a refused decryption request from the
same origin land on the same node, which is what makes the joined view useful
without merging any identities.
"""
from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.engine.classify import CROSS_LAYER_RULES
from phantom.engine.graph import build_graph, summarize
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.shadow import is_adversarial, temporal
from phantom.shadow.models import ShadowEvent

SUBJECT_PREFIX = "protected:"


def _origin_key(hmac: str) -> str:
    return f"origin:{hmac[:12]}"


def _client_key(value: str) -> str:
    return f"client:{value[:12]}"


def subject_key(subject_ref: str) -> str:
    return f"{SUBJECT_PREFIX}{subject_ref}"


def project(session: Session) -> dict:
    """Fold every shadow event into nodes and edges. Idempotent."""
    engine = RelationshipEngine(session)
    events = session.scalars(
        select(ShadowEvent).order_by(ShadowEvent.occurred_at)
    ).all()

    origins_to_subjects: dict[str, set[str]] = defaultdict(set)

    for event in events:
        subject = subject_key(event.subject_ref)
        engine._node(
            subject,
            event.subject_kind,
            event.subject_ref,
            {
                "layer": "adversarial",
                "subject_ref": event.subject_ref,
                "first_observed": event.occurred_at.isoformat(),
            },
        )

        if not event.origin_hmac:
            continue

        origin = _origin_key(event.origin_hmac)
        engine._node(
            origin,
            "origin",
            f"origin…{event.origin_hmac[:6]}",
            {"layer": "adversarial", "role": "network-origin", "pseudonymous": True},
        )
        engine._edge(
            "R-SHD-1",
            origin,
            subject,
            evidence_kind=event.kind,
            detail=(
                f"{event.kind} on {event.subject_ref}: {event.outcome}"
                + (f" using {event.client_tool}" if event.client_tool else "")
            ),
            source_ref=f"shadow:{event.event_hash[:16]}",
            payload={
                "outcome": event.outcome,
                "occurred_at": event.occurred_at.isoformat(),
                "event_hash": event.event_hash,
                "vault_seq": event.vault_seq,
            },
            base_confidence=0.7,
            observed_at=event.occurred_at,
        )
        origins_to_subjects[origin].add(subject)

        if event.client_hash:
            client = _client_key(event.client_hash)
            engine._node(
                client,
                "client",
                event.client_family
                + (f" · {event.client_tool}" if event.client_tool else ""),
                {"layer": "adversarial", "family": event.client_family,
                 "tool": event.client_tool},
            )
            engine._edge(
                "R-MIR-2",
                origin,
                client,
                evidence_kind="client_presented",
                detail=f"Origin presented client stack '{event.client_family}'",
                source_ref=f"shadow:{event.event_hash[:16]}:client",
                base_confidence=0.8,
                observed_at=event.occurred_at,
            )

        if event.asn is not None:
            asn = f"asn:{event.asn}"
            engine._node(
                asn, "asn", event.asn_org or f"AS{event.asn}",
                {"layer": "adversarial", "asn": event.asn, "org": event.asn_org},
            )
            engine._edge(
                "R-MIR-3",
                origin,
                asn,
                evidence_kind="asn_resolution",
                detail=f"Resolved to AS{event.asn} using the local ASN table",
                source_ref=f"shadow:{event.event_hash[:16]}:asn",
                base_confidence=0.7,
                observed_at=event.occurred_at,
            )

    # Recurrence: one origin reaching several protected objects.
    recurrence = 0
    for origin, subjects in origins_to_subjects.items():
        if len(subjects) < 2:
            continue
        ordered = sorted(subjects)
        for i, first in enumerate(ordered):
            for second in ordered[i + 1:]:
                engine._edge(
                    "R-SHD-2",
                    first,
                    second,
                    evidence_kind="shared_origin",
                    detail=f"Both protected objects were reached from {origin}",
                    source_ref=f"recur:{origin}:{first}:{second}",
                    base_confidence=0.45,
                )
                recurrence += 1

    # Temporal proximity, per candidate returned by the analysis.
    co_occurrence = 0
    for candidate in temporal.co_occurrences(session):
        a, b = (subject_key(s) for s in candidate["subjects"])
        engine._edge(
            "R-SHD-3",
            a,
            b,
            evidence_kind="temporal_proximity",
            detail=(
                f"Reached {candidate['gap_minutes']} minute(s) apart via "
                f"{candidate['indicator']}"
            ),
            source_ref=f"temporal:{candidate['indicator']}:{a}:{b}",
            base_confidence=candidate["confidence"],
        )
        co_occurrence += 1

    session.commit()
    return {
        "events": len(events),
        "recurrence_edges": recurrence,
        "co_occurrence_edges": co_occurrence,
    }


def to_cytoscape(session: Session, *, include_surveillance: bool = False) -> dict:
    """Layer 3 view. Surveillance nodes appear only through confirmed bridges."""
    full = build_graph(session)
    keep = {k for k, data in full.nodes(data=True) if is_adversarial(data["kind"])}

    if include_surveillance:
        for src, dst, data in full.edges(data=True):
            if data["rule_id"] in CROSS_LAYER_RULES:
                keep.update({src, dst})

    sub = full.subgraph(keep)

    # Bridges are reported as metadata even when their surveillance endpoint is
    # not displayed: the join exists, and hiding that would be its own kind of
    # dishonesty. The edge itself only becomes an element when both ends are in
    # view.
    all_bridges = [
        {
            "edge_id": data["id"],
            "from": src,
            "to": dst,
            "confidence": data["confidence"],
            "caveat": data.get("caveat"),
            "endpoints_visible": src in keep and dst in keep,
        }
        for src, dst, data in full.edges(data=True)
        if data["rule_id"] in CROSS_LAYER_RULES
    ]

    elements = []
    for key, data in sub.nodes(data=True):
        elements.append(
            {
                "data": {
                    "id": key,
                    "label": data.get("label", key),
                    "kind": data.get("kind"),
                    "layer": "adversarial" if is_adversarial(data["kind"]) else "surveillance",
                    "degree": sub.degree(key),
                }
            }
        )
    drawn_bridges = []
    for src, dst, data in sub.edges(data=True):
        is_bridge = data["rule_id"] in CROSS_LAYER_RULES
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
                    "cross_layer": is_bridge,
                }
            }
        )
        if is_bridge:
            drawn_bridges.append(data["id"])

    return {
        "elements": elements,
        "stats": summarize(sub),
        "confirmed_bridges": all_bridges,
        "bridges_drawn": drawn_bridges,
        "legend": {
            "protected": "A decoy or locked object. The thing being defended.",
            "origin": "A pseudonymous network origin, HMAC only by default.",
            "client": "A client stack, never a person.",
            "asn": "A network from your local table.",
        },
        "separation": {
            "automatic_merges": 0,
            "rule": (
                "A surveillance entity and an adversarial entity are distinct nodes "
                "unless a human confirmed a proposal. Ingestion cannot create the "
                "edge; the relationship engine raises."
            ),
            "cross_layer_rule": sorted(CROSS_LAYER_RULES),
        },
    }

"""The only sanctioned path between Layer 3 and Layers 1-2.

The relationship engine refuses to write a cross-layer edge during ingestion, so
this module is not a convenience wrapper: it is the sole route, and it requires a
human decision on the record.

A proposal is not a conclusion. Confirming one produces the weakest edge in the
graph, capped at the hypothesis ceiling, carrying a caveat that names the innocent
explanations out loud.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.engine.relationship_engine import RelationshipEngine
from phantom.models import Node
from phantom.shadow import LAYER_ADVERSARIAL, LAYER_SURVEILLANCE, layer_of
from phantom.shadow.models import BridgeProposal

RULE = "R-SHD-4"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _node(session: Session, key: str) -> Node:
    node = session.scalar(select(Node).where(Node.key == key))
    if node is None:
        raise LookupError(f"no such node: {key}")
    return node


def propose(
    session: Session,
    *,
    surveillance_key: str,
    adversarial_key: str,
    rationale: str,
    evidence_refs: list[str] | None = None,
    proposed_by: str = "owner",
) -> BridgeProposal:
    left = _node(session, surveillance_key)
    right = _node(session, adversarial_key)
    if layer_of(left.kind) != LAYER_SURVEILLANCE or layer_of(right.kind) != LAYER_ADVERSARIAL:
        raise ValueError(
            "a bridge joins one surveillance-layer entity to one adversarial-layer "
            f"entity; got {left.kind} -> {right.kind}"
        )
    if len((rationale or "").strip()) < 15:
        raise ValueError(
            "state the shared observable behind this proposal; a bridge with no "
            "stated indicator is a guess with paperwork"
        )

    for existing in session.scalars(
        select(BridgeProposal).where(
            BridgeProposal.surveillance_key == surveillance_key,
            BridgeProposal.adversarial_key == adversarial_key,
        )
    ):
        if existing.status in {"proposed", "confirmed"}:
            return existing

    proposal = BridgeProposal(
        surveillance_key=surveillance_key,
        adversarial_key=adversarial_key,
        rationale=rationale.strip(),
        evidence_refs=evidence_refs or [],
    )
    session.add(proposal)
    session.commit()
    return proposal


def confirm(
    session: Session, proposal_id: str, *, by: str = "owner", note: str = ""
) -> dict:
    """Turn a reviewed proposal into exactly one edge. Nothing else happens."""
    proposal = session.get(BridgeProposal, proposal_id)
    if proposal is None:
        raise LookupError("no such proposal")
    if proposal.status == "rejected":
        raise ValueError("this proposal was rejected; propose it again to reopen it")
    if proposal.status == "confirmed" and proposal.edge_id:
        return {"status": "confirmed", "edge_id": proposal.edge_id, "already": True}

    engine = RelationshipEngine(session)
    edge = engine._edge(
        RULE,
        proposal.surveillance_key,
        proposal.adversarial_key,
        evidence_kind="confirmed_bridge",
        detail=(
            f"Bridge confirmed by {by}. Stated shared observable: {proposal.rationale}"
            + (f" Decision note: {note}" if note else "")
        ),
        source_ref=f"bridge:{proposal.id}",
        payload={"rationale": proposal.rationale, "evidence_refs": proposal.evidence_refs},
        base_confidence=0.35,
        confirmed=True,
    )
    proposal.status = "confirmed"
    proposal.decided_at = _now()
    proposal.decided_by = by
    proposal.decided_note = note
    proposal.edge_id = edge.id
    session.commit()
    return {
        "status": "confirmed",
        "edge_id": edge.id,
        "confidence": edge.confidence,
        "caveat": edge.caveat,
    }


def reject(
    session: Session, proposal_id: str, *, by: str = "owner", note: str = ""
) -> dict:
    proposal = session.get(BridgeProposal, proposal_id)
    if proposal is None:
        raise LookupError("no such proposal")
    proposal.status = "rejected"
    proposal.decided_at = _now()
    proposal.decided_by = by
    proposal.decided_note = note
    session.commit()
    return {"status": "rejected", "proposal_id": proposal.id}


def reapply(session: Session) -> dict:
    """Restore the edge for every already-confirmed decision after a rebuild.

    This is not a second decision. The human judgement is already in the row,
    with its note and its timestamp, so re-deriving the graph replays it instead
    of losing it or re-asking.
    """
    restored = 0
    skipped: list[str] = []
    engine = RelationshipEngine(session)

    for proposal in session.scalars(
        select(BridgeProposal).where(BridgeProposal.status == "confirmed")
    ):
        left = session.scalar(select(Node).where(Node.key == proposal.surveillance_key))
        right = session.scalar(select(Node).where(Node.key == proposal.adversarial_key))
        if left is None or right is None:
            # The observation behind one end no longer exists. Say so rather than
            # resurrecting a node from a proposal.
            skipped.append(proposal.id)
            proposal.edge_id = None
            continue

        proposal.edge_id = None
        edge = engine._edge(
            RULE,
            proposal.surveillance_key,
            proposal.adversarial_key,
            evidence_kind="confirmed_bridge",
            detail=(
                f"Bridge confirmed by {proposal.decided_by or 'owner'}. "
                f"Stated shared observable: {proposal.rationale}"
                + (f" Decision note: {proposal.decided_note}" if proposal.decided_note else "")
            ),
            source_ref=f"bridge:{proposal.id}",
            payload={"rationale": proposal.rationale, "evidence_refs": proposal.evidence_refs},
            base_confidence=0.35,
            confirmed=True,
        )
        proposal.edge_id = edge.id
        restored += 1

    session.commit()
    return {"restored": restored, "skipped": skipped}


def serialize(proposal: BridgeProposal) -> dict:
    return {
        "id": proposal.id,
        "surveillance_key": proposal.surveillance_key,
        "adversarial_key": proposal.adversarial_key,
        "rationale": proposal.rationale,
        "evidence_refs": proposal.evidence_refs,
        "status": proposal.status,
        "proposed_at": proposal.proposed_at.isoformat(),
        "decided_by": proposal.decided_by,
        "decided_note": proposal.decided_note,
        "edge_id": proposal.edge_id,
    }


def list_proposals(session: Session, *, status: str | None = None) -> list[dict]:
    query = select(BridgeProposal).order_by(BridgeProposal.proposed_at.desc())
    if status:
        query = query.where(BridgeProposal.status == status)
    return [serialize(p) for p in session.scalars(query)]

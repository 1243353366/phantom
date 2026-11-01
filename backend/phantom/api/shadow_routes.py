"""ShadowTrace endpoints.

Three groups, deliberately separated:

  /api/shadow/events, indicators, report   what Layer 3 observed
  /api/shadow/bridges                      the human decision that joins layers
  /api/shadow/mirrorlock, quarantine       the protections themselves
"""
from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from phantom.db import get_session
from phantom.shadow import bridges, graph, indicators, mirrorlock, quarantine, temporal, vault
from phantom.shadow import report as shadow_report

router = APIRouter(prefix="/api/shadow")


def db() -> Session:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


class BridgeRequest(BaseModel):
    surveillance_key: str
    adversarial_key: str
    rationale: str = Field(description="The shared observable behind this proposal")
    evidence_refs: list[str] = []


class DecisionRequest(BaseModel):
    by: str = "owner"
    note: str = ""


class LockRequest(BaseModel):
    label: str
    content_b64: str


class AccessRequest(BaseModel):
    requester_label: str = "unidentified"
    justification: str = ""
    origin_hmac: str | None = None
    client_hash: str | None = None
    client_family: str = ""
    client_tool: str = ""
    asn: int | None = None


class GrantRequest(BaseModel):
    minutes: int = 15
    note: str = ""
    #: Printed by `phantom approve <blob_id> --minutes N` on the host holding the
    #: local key. Without it this endpoint cannot create a grant, which is the
    #: whole point: requesting a read and authorising one are different acts and
    #: must not be the same unauthenticated POST.
    approval: str = ""
    granted_by: str = ""


class QuarantineRequest(BaseModel):
    payload_b64: str
    source_ref: str = ""
    declared_type: str = ""


@router.get("/events")
def events(limit: int = 200, session: Session = Depends(db)) -> dict:
    from sqlalchemy import select

    from phantom.shadow.models import ShadowEvent

    rows = session.scalars(
        select(ShadowEvent).order_by(ShadowEvent.occurred_at.desc()).limit(limit)
    ).all()
    return {
        "events": [
            {
                "event_hash": row.event_hash,
                "kind": row.kind,
                "outcome": row.outcome,
                "subject_ref": row.subject_ref,
                "occurred_at": row.occurred_at.isoformat(),
                "origin": (row.origin_hmac or "")[:12],
                "client_family": row.client_family,
                "client_tool": row.client_tool,
                "asn": row.asn,
                "detail": row.detail,
                "alt_explanations": row.alt_explanations,
                "vault_seq": row.vault_seq,
                "credential_material_refused": row.credential_material_refused,
            }
            for row in rows
        ]
    }


@router.get("/report")
def report(session: Session = Depends(db)) -> dict:
    graph.project(session)
    payload = shadow_report.adversarial_report(session)
    payload["rule_catalogue"] = shadow_report.rule_catalogue()
    return payload


@router.get("/indicators")
def recurring_indicators(session: Session = Depends(db)) -> dict:
    return {
        "indicators": indicators.recurring(session),
        "co_occurrences": temporal.co_occurrences(session),
    }


@router.get("/graph")
def shadow_graph(include_surveillance: bool = False, session: Session = Depends(db)) -> dict:
    graph.project(session)
    return graph.to_cytoscape(session, include_surveillance=include_surveillance)


@router.get("/vault")
def verify_vault(session: Session = Depends(db)) -> dict:
    return vault.verify(session)


@router.get("/bridges")
def list_bridges(status: str | None = None, session: Session = Depends(db)) -> dict:
    return {"proposals": bridges.list_proposals(session, status=status)}


@router.post("/bridges")
def create_bridge(body: BridgeRequest, session: Session = Depends(db)) -> dict:
    try:
        proposal = bridges.propose(
            session,
            surveillance_key=body.surveillance_key,
            adversarial_key=body.adversarial_key,
            rationale=body.rationale,
            evidence_refs=body.evidence_refs,
        )
    except (LookupError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return bridges.serialize(proposal)


@router.post("/bridges/{proposal_id}/confirm")
def confirm_bridge(
    proposal_id: str, body: DecisionRequest, session: Session = Depends(db)
) -> dict:
    try:
        return bridges.confirm(session, proposal_id, by=body.by, note=body.note)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/bridges/{proposal_id}/reject")
def reject_bridge(
    proposal_id: str, body: DecisionRequest, session: Session = Depends(db)
) -> dict:
    try:
        return bridges.reject(session, proposal_id, by=body.by, note=body.note)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/mirrorlock")
def lock_object(body: LockRequest, session: Session = Depends(db)) -> dict:
    blob = mirrorlock.lock(session, body.label, base64.b64decode(body.content_b64))
    return {
        "blob_id": blob.id,
        "label": blob.label,
        "size_bytes": blob.size_bytes,
        "digest": blob.plaintext_digest,
        "note": "Encrypted against the local key. Decryption is denied by default.",
    }


@router.post("/mirrorlock/{blob_id}/request")
def request_access(
    blob_id: str, body: AccessRequest, session: Session = Depends(db)
) -> dict:
    try:
        return mirrorlock.request(
            session,
            blob_id,
            requester_label=body.requester_label,
            justification=body.justification,
            origin_hmac=body.origin_hmac,
            client_hash=body.client_hash,
            client_family=body.client_family,
            client_tool=body.client_tool,
            asn=body.asn,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/mirrorlock/{blob_id}/grant")
def grant_access(
    blob_id: str, body: GrantRequest, session: Session = Depends(db)
) -> dict:
    try:
        grant = mirrorlock.grant(
            session,
            blob_id,
            minutes=body.minutes,
            approval=body.approval,
            granted_by=body.granted_by,
            note=body.note,
        )
    except mirrorlock.NotAuthorised as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "grant_id": grant.id,
        "expires_at": grant.expires_at.isoformat(),
        "granted_by": grant.granted_by,
        "authorization": grant.authorization,
    }


@router.post("/mirrorlock/{blob_id}/revoke")
def revoke_access(blob_id: str, session: Session = Depends(db)) -> dict:
    return {"revoked": mirrorlock.revoke(session, blob_id)}


@router.post("/quarantine")
def quarantine_payload(body: QuarantineRequest, session: Session = Depends(db)) -> dict:
    return quarantine.capture(
        session,
        base64.b64decode(body.payload_b64),
        source_ref=body.source_ref,
        declared_type=body.declared_type,
    )

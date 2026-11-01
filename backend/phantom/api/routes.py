"""HTTP surface.

Every endpoint is local. There is no endpoint that forwards data to a third
party, and no endpoint that sends mail on anyone's behalf.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from phantom import egress
from phantom.api.schemas import (
    EnrollRequest,
    EnrollResponse,
    ExposureRequest,
    IngestRequest,
)
from phantom.auth.consent import ConsentError, ConsentService
from phantom.collector.gmail import authorization_url
from phantom.collector.headers import parse_eml
from phantom.db import get_session
from phantom.engine.graph import explain_edge, to_cytoscape
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.exposure.local_contacts import ContactExposureAnalyzer
from phantom.selfaudit.auditor import SelfAuditor
from phantom.watchdog.negative_space import NegativeSpaceWatchdog

router = APIRouter(prefix="/api")


def db() -> Session:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


@router.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "outbound_hosts_allowed": [row["host"] for row in SelfAuditor().declared_egress()],
        "sends_email": False,
        "uploads_contacts": False,
    }


@router.post("/ingest/eml")
def ingest_eml(body: IngestRequest, session: Session = Depends(db)) -> dict:
    mail = parse_eml(body.raw_email)
    engine = RelationshipEngine(session)
    result = engine.ingest(mail, source_ref=body.source_ref)
    engine.correlate()
    return {
        "ingested": result,
        "message_id": mail.message_id,
        "sender": mail.from_domain,
        "pixels": [
            {"host": p.host, "reasons": p.reasons, "confidence": p.confidence}
            for p in mail.pixels
        ],
        "redirectors": [
            {"host": link.host, "target": link.target_host, "reasons": link.reasons}
            for link in mail.links if link.is_redirector
        ],
        "dmarc": result["dmarc"],
    }


@router.get("/graph")
def graph(session: Session = Depends(db)) -> dict:
    return to_cytoscape(session)


@router.get("/graph/edge/{edge_id}")
def edge_detail(edge_id: str, session: Session = Depends(db)) -> dict:
    detail = explain_edge(session, edge_id)
    if "error" in detail:
        raise HTTPException(status_code=404, detail=detail["error"])
    return detail


@router.get("/negative-space")
def negative_space(session: Session = Depends(db)) -> dict:
    return NegativeSpaceWatchdog(session).report()


@router.post("/negative-space/scan")
def negative_space_scan(session: Session = Depends(db)) -> dict:
    events = NegativeSpaceWatchdog(session).scan()
    return {"new_events": len(events), "report": NegativeSpaceWatchdog(session).report()}


@router.get("/selfaudit")
def self_audit(session: Session = Depends(db)) -> dict:
    return SelfAuditor(session).run()


@router.get("/egress")
def egress_log(limit: int = Query(default=200, le=2000)) -> dict:
    return {"entries": egress.read_log()[-limit:]}


@router.get("/auth/gmail/start")
def gmail_start(client_id: str, redirect_uri: str, state: str,
                body_tier: bool = False) -> dict:
    return {
        "authorization_url": authorization_url(
            client_id=client_id, redirect_uri=redirect_uri, state=state, body_tier=body_tier
        ),
        "tier": "body (gmail.readonly)" if body_tier else "metadata (gmail.metadata)",
        "cannot": ["send mail", "modify or delete mail", "read contacts", "read drive"],
    }


@router.post("/consent/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, session: Session = Depends(db)) -> EnrollResponse:
    service = ConsentService(session)
    try:
        record = service.enroll(
            gmail_address=body.gmail_address,
            phone_number=body.phone_number,
            work_email=body.work_email,
            consent_gmail=body.consent_gmail,
            consent_phone=body.consent_phone,
            consent_work_email=body.consent_work_email,
            ttl_days=body.ttl_days,
        )
    except ConsentError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    stored = [
        name
        for name, value in (
            ("gmail_address", body.gmail_address),
            ("phone_number", body.phone_number),
            ("work_email", body.work_email),
        )
        if value
    ]
    return EnrollResponse(
        id=record.id,
        receipt_hash=record.receipt_hash,
        granted_at=record.granted_at.isoformat(),
        channels_authorised=record.scopes.get("channels_authorised", []),
        stored_fields=stored,
        not_stored=[f for f in ("gmail_address", "phone_number", "work_email") if f not in stored],
        purpose=record.purpose,
        policy_version=record.policy_version,
        how_to_revoke=f"POST /api/consent/{record.id}/revoke",
    )


@router.get("/consent/{consent_id}")
def consent_view(consent_id: str, session: Session = Depends(db)) -> dict:
    record = session.get(
        __import__("phantom.models", fromlist=["ConsentRecord"]).ConsentRecord, consent_id
    )
    if record is None:
        raise HTTPException(status_code=404, detail="no such consent record")
    return ConsentService(session).view(record)


@router.post("/consent/{consent_id}/revoke")
def consent_revoke(consent_id: str, session: Session = Depends(db)) -> dict:
    try:
        record = ConsentService(session).revoke(consent_id)
    except ConsentError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"revoked_at": record.revoked_at.isoformat(), "fields_cleared": True}


@router.post("/exposure/scan")
def exposure_scan(body: ExposureRequest, session: Session = Depends(db)) -> dict:
    analyzer = ContactExposureAnalyzer(session)
    result = analyzer.analyze_csv(
        body.contacts_csv,
        exclude_domains=set(body.exclude_domains),
        exclude_categories=set(body.exclude_categories),
    )
    return result.as_dict()

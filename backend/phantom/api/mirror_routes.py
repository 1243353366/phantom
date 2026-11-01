"""Canary endpoints.

Two surfaces with different audiences:

  /mirror/b/{token}.gif   the decoy. Public by design, answers like any image.
  /api/mirror/*           your console. Never exposes a raw address unless you
                          explicitly turned that on.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from phantom.db import get_session
from phantom.mirror import countergraph, tokens
from phantom.mirror.beacon import (
    TRANSPARENT_GIF,
    CapReached,
    UnknownCanary,
    purge_expired,
    record_observation,
)
from phantom.mirror.report import asymmetry_report

console = APIRouter(prefix="/api/mirror")
decoy = APIRouter()


def db() -> Session:
    session = get_session()
    try:
        yield session
    finally:
        session.close()


class CanaryRequest(BaseModel):
    label: str = Field(description="Where this canary is being placed, e.g. 'pitch-deck v3 / acme'")
    note: str = ""


@console.post("/canary")
def create_canary(body: CanaryRequest, session: Session = Depends(db)) -> dict:
    try:
        canary = tokens.mint(session, body.label, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "label": canary.label,
        "url": canary.url,
        "placement_note": (
            "Embed as a remote image. The token is opaque: anyone who sees the URL "
            "learns nothing about which document it came from."
        ),
    }


@console.post("/canary/{token}/revoke")
def revoke_canary(token: str, session: Session = Depends(db)) -> dict:
    if not tokens.revoke(session, token):
        raise HTTPException(status_code=404, detail="no such canary")
    return {"revoked": True}


@console.get("/observations")
def observations(limit: int = 200, session: Session = Depends(db)) -> dict:
    report = asymmetry_report(session)
    return {"report": report, "limit": limit}


@console.get("/graph")
def graph(session: Session = Depends(db)) -> dict:
    countergraph.build(session)
    return countergraph.to_cytoscape(session)


@console.get("/report")
def report(session: Session = Depends(db)) -> dict:
    countergraph.build(session)
    return asymmetry_report(session)


@console.post("/purge")
def purge(session: Session = Depends(db)) -> dict:
    return {"deleted": purge_expired(session)}


@decoy.get("/mirror/b/{filename}")
def beacon(filename: str, request: Request, session: Session = Depends(db)) -> Response:
    """Answer like an image, whatever the client turns out to be.

    Always returns the GIF, even for an unknown token: a 404 would tell a prober
    that it had been detected, which is the one thing they would want to know.
    """
    token = filename[:-4] if filename.endswith(".gif") else filename
    headers = dict(request.headers)
    source_ip = request.client.host if request.client else "0.0.0.0"

    delay_ms = 0
    try:
        _, delay_ms = record_observation(
            session,
            token=token,
            source_ip=source_ip,
            headers=headers,
            method=request.method,
            path=request.url.path,
        )
    except (UnknownCanary, CapReached):
        # Answer identically whether the token is real, unknown or over budget.
        pass

    if delay_ms:
        time.sleep(delay_ms / 1000)

    return Response(
        content=TRANSPARENT_GIF,
        media_type="image/gif",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )

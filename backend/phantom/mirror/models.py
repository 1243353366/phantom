"""Storage for counter-observation.

Note what is absent: no raw IP unless explicitly enabled, no cookies, no request
bodies, no query strings, no JavaScript fingerprint. Only what a plain HTTP
request volunteers to any server.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from phantom.db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class CanaryToken(Base):
    __tablename__ = "canary_tokens"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    signature: Mapped[str] = mapped_column(String(64))
    #: Which document, copy or recipient this canary was placed in.
    label: Mapped[str] = mapped_column(String(200))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MirrorObservation(Base):
    """One request that touched a canary."""

    __tablename__ = "mirror_observations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    token_id: Mapped[str] = mapped_column(ForeignKey("canary_tokens.id"), index=True)
    received_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    #: HMAC of the source address. Stable for correlation, useless if leaked.
    origin_hmac: Mapped[str] = mapped_column(String(64), index=True)
    #: Only populated when retain_raw_ip is explicitly enabled.
    origin_raw: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    asn_org: Mapped[str | None] = mapped_column(String(200), nullable=True)
    client_hash: Mapped[str] = mapped_column(String(64), index=True)
    client_family: Mapped[str] = mapped_column(String(64))
    client_tool: Mapped[str] = mapped_column(String(64), default="")
    #: Heuristics that suggest a collector rather than a person.
    extraction_signals: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    path: Mapped[str] = mapped_column(String(400), default="")
    method: Mapped[str] = mapped_column(String(8), default="GET")
    tarpit_ms: Mapped[int] = mapped_column(Integer, default=0)

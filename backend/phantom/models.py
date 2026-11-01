"""Persistence layer.

Design rule: a graph edge without provenance is a bug. Edges cannot exist
without at least one :class:`Evidence` row, and the relationship engine is the
only writer that creates them.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from phantom.db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Node(Base):
    """A thing in the graph: an organization, a domain, a provider, a mailbox."""

    __tablename__ = "nodes"
    __table_args__ = (UniqueConstraint("key", name="uq_node_key"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    key: Mapped[str] = mapped_column(String(320), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    label: Mapped[str] = mapped_column(String(320))
    attrs: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Evidence(Base):
    """A single observation supporting (or weakening) an edge.

    Stored so the UI can show *why* an edge exists, down to the header or HTML
    attribute it came from.
    """

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    edge_id: Mapped[str] = mapped_column(ForeignKey("edges.id"), index=True)
    kind: Mapped[str] = mapped_column(String(48))
    detail: Mapped[str] = mapped_column(Text)
    source_ref: Mapped[str | None] = mapped_column(String(320), nullable=True)
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # SHA-256 of the raw snippet, so a claim can be checked without storing the
    # raw email body.
    snippet_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    edge: Mapped["Edge"] = relationship(back_populates="evidence")


class Edge(Base):
    """A relationship, always carrying its classification and its proof."""

    __tablename__ = "edges"
    __table_args__ = (
        UniqueConstraint("src_key", "dst_key", "relation", name="uq_edge"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    src_key: Mapped[str] = mapped_column(String(320), index=True)
    dst_key: Mapped[str] = mapped_column(String(320), index=True)
    relation: Mapped[str] = mapped_column(String(48))
    # observed | correlated | hypothesized
    classification: Mapped[str] = mapped_column(String(16), index=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # Human-readable caveat shown next to every non-observed edge.
    caveat: Mapped[str | None] = mapped_column(Text, nullable=True)

    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="edge", cascade="all, delete-orphan"
    )


class NegativeSpaceEvent(Base):
    """Something that stopped being visible. An observation, not a conclusion."""

    __tablename__ = "negative_space_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    subject_key: Mapped[str] = mapped_column(String(320), index=True)
    node_key: Mapped[str] = mapped_column(String(320), index=True)
    change: Mapped[str] = mapped_column(String(48))
    window_from: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    window_to: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    before_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    after_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Always True on purpose. PHANTOM records disappearance, it does not
    # explain it.
    cause_unknown: Mapped[bool] = mapped_column(default=True)
    note: Mapped[str] = mapped_column(Text, default="")


class ConsentRecord(Base):
    """An explicit, revocable, purpose-bound permission grant.

    This is the only path by which a person's Gmail address, phone number or
    work email enters PHANTOM, and each field is consented to separately.
    """

    __tablename__ = "consent_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    subject_token: Mapped[str] = mapped_column(String(64), index=True)
    gmail_address: Mapped[str | None] = mapped_column(String(320), nullable=True)
    phone_number: Mapped[str | None] = mapped_column(String(32), nullable=True)
    work_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    scopes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    purpose: Mapped[str] = mapped_column(String(320))
    policy_version: Mapped[str] = mapped_column(String(16), default="1.0")
    granted_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    receipt_hash: Mapped[str] = mapped_column(String(64))


class SelfAuditRun(Base):
    """Snapshot of PHANTOM's own surveillance footprint."""

    __tablename__ = "self_audit_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    run_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    egress_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

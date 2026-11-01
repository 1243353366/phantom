"""Persistence for Layer 3.

Everything here is infrastructure observation. There is deliberately no column
for a name, an account, an email address or any identifier of a person, so a
future feature cannot quietly start filling one in.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from phantom.db import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class ShadowEvent(Base):
    """One observable interaction with defensive infrastructure.

    ``event_hash`` is content addressed: it is a digest of the normalised
    observation, so re-ingesting the same observation is a no-op and a mutated
    row no longer matches its own fingerprint.
    """

    __tablename__ = "shadow_events"
    __table_args__ = (UniqueConstraint("event_hash", name="uq_shadow_event_hash"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    event_hash: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(48), index=True)
    outcome: Mapped[str] = mapped_column(String(32), default="observed")
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )

    # Which protected thing was touched. Never the thing itself.
    subject_ref: Mapped[str] = mapped_column(String(320), index=True)
    subject_kind: Mapped[str] = mapped_column(String(32), default="protected_object")

    # Observable infrastructure. Pseudonymous by construction.
    origin_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    client_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    client_family: Mapped[str] = mapped_column(String(64), default="")
    client_tool: Mapped[str] = mapped_column(String(64), default="")
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    asn_org: Mapped[str | None] = mapped_column(String(160), nullable=True)

    detail: Mapped[str] = mapped_column(Text, default="")
    #: Mandatory. An event with no alternative explanation is an event that has
    #: already been over-read.
    alt_explanations: Mapped[list[str]] = mapped_column(JSON, default=list)
    payload_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Set when the request carried credential-looking material that was stripped
    #: before storage. PHANTOM never keeps recovered credentials.
    credential_material_refused: Mapped[bool] = mapped_column(Boolean, default=False)
    vault_seq: Mapped[int | None] = mapped_column(Integer, nullable=True)


class VaultRecord(Base):
    """Append-only link in the evidence hash chain."""

    __tablename__ = "vault_records"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_hash: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(48))
    subject_ref: Mapped[str] = mapped_column(String(320))
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    prev_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ProtectedBlob(Base):
    """MirrorLock: content encrypted against the local key, never sent anywhere."""

    __tablename__ = "protected_blobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    label: Mapped[str] = mapped_column(String(320))
    ciphertext: Mapped[str] = mapped_column(Text)
    plaintext_digest: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AccessGrant(Base):
    """An explicit, revocable, expiring permission to decrypt one blob.

    Decryption is denied unless a row here is live. The default for every
    request is denial.
    """

    __tablename__ = "access_grants"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    blob_id: Mapped[str] = mapped_column(ForeignKey("protected_blobs.id"), index=True)
    granted_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(Text, default="")


class QuarantinedPayload(Base):
    """A payload kept for evidence only. Stored encrypted, never executed."""

    __tablename__ = "quarantined_payloads"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    digest: Mapped[str] = mapped_column(String(64), index=True)
    ciphertext: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    declared_type: Mapped[str] = mapped_column(String(120), default="")
    sniffed_type: Mapped[str] = mapped_column(String(120), default="")
    executable_signature: Mapped[bool] = mapped_column(Boolean, default=False)
    source_ref: Mapped[str] = mapped_column(String(320), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class BridgeProposal(Base):
    """A proposed join between a surveillance entity and an adversarial entity.

    Lives in its own table precisely so that the join cannot happen implicitly.
    Until ``status == "confirmed"``, no edge exists.
    """

    __tablename__ = "bridge_proposals"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    surveillance_key: Mapped[str] = mapped_column(String(320), index=True)
    adversarial_key: Mapped[str] = mapped_column(String(320), index=True)
    rationale: Mapped[str] = mapped_column(Text)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: proposed | confirmed | rejected
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    proposed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    decided_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decided_by: Mapped[str] = mapped_column(String(120), default="")
    decided_note: Mapped[str] = mapped_column(Text, default="")
    edge_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

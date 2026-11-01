"""The evidence vault: an append-only hash chain.

Why a chain rather than a normal table: the value of an adversarial record is
that it still means something after the fact. A row that can be edited in place
proves nothing, and a plain log with a checksum column proves nothing either,
because the checksum can be recomputed. Each record therefore commits to its
predecessor *and* is sealed with a key that never leaves this machine, so
editing history requires the key.

Two failure modes this catches:

  edit      a stored event was modified after the fact
  splice    records were deleted or reordered

What it cannot catch: a full rewrite by someone holding the local key. There is
no external timestamping authority here, by design. If you need that, hash the
chain head somewhere you don't control.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom import crypto
from phantom.shadow.models import VaultRecord

GENESIS = "0" * 64


def _iso(value: dt.datetime) -> str:
    """Canonical UTC timestamp. Naive values from SQLite are treated as UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).replace(microsecond=value.microsecond).isoformat()


def _seal(prev_hash: str, event_hash: str, kind: str, subject_ref: str, occurred_at: dt.datetime) -> str:
    material = "|".join([prev_hash, event_hash, kind, subject_ref, _iso(occurred_at)])
    return crypto.hmac_hex(material, domain="vault-chain")


def head(session: Session) -> VaultRecord | None:
    return session.scalars(
        select(VaultRecord).order_by(VaultRecord.seq.desc()).limit(1)
    ).first()


def append(
    session: Session,
    *,
    event_hash: str,
    kind: str,
    subject_ref: str,
    occurred_at: dt.datetime,
) -> VaultRecord:
    previous = head(session)
    prev_hash = previous.record_hash if previous else GENESIS
    record = VaultRecord(
        event_hash=event_hash,
        kind=kind,
        subject_ref=subject_ref,
        occurred_at=occurred_at,
        prev_hash=prev_hash,
        record_hash=_seal(prev_hash, event_hash, kind, subject_ref, occurred_at),
    )
    session.add(record)
    session.flush()
    return record


def verify(session: Session) -> dict:
    """Recompute the whole chain. Returns where it first breaks, if it does."""
    records = session.scalars(select(VaultRecord).order_by(VaultRecord.seq)).all()
    if not records:
        return {
            "ok": True,
            "checked": 0,
            "head": GENESIS,
            "reason": "nothing recorded yet",
        }

    expected_prev = GENESIS
    for record in records:
        if record.prev_hash != expected_prev:
            return {
                "ok": False,
                "checked": records.index(record),
                "first_bad_seq": record.seq,
                "reason": (
                    "chain link broken: this record does not point at its "
                    "predecessor, so a record was removed, inserted or reordered"
                ),
                "head": records[-1].record_hash,
            }
        resealed = _seal(
            record.prev_hash, record.event_hash, record.kind, record.subject_ref,
            record.occurred_at,
        )
        if resealed != record.record_hash:
            return {
                "ok": False,
                "checked": records.index(record),
                "first_bad_seq": record.seq,
                "reason": (
                    "seal mismatch: this record's contents changed after it was "
                    "written, and the local key was not used to reseal it"
                ),
                "head": records[-1].record_hash,
            }
        expected_prev = record.record_hash

    return {
        "ok": True,
        "checked": len(records),
        "head": records[-1].record_hash,
        "reason": "every record reseals to its stored seal and links to its predecessor",
    }

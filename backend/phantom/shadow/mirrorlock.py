"""MirrorLock: cryptographic protection with a refusal log.

The lock is ordinary: content encrypted against the local Fernet key. The
interesting part is the broker. Every request to decrypt is recorded, whether it
succeeds or fails, because a refused request is the single most informative
event in Layer 3 and the easiest one to lose.

Default is denial. A request succeeds only while a live, unrevoked grant exists.
There is no path where a caller supplies its own authorisation.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom import crypto
from phantom.shadow import events as shadow_events
from phantom.shadow.models import AccessGrant, ProtectedBlob


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _as_bytes(value: bytes | str) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def lock(session: Session, label: str, plaintext: bytes | str, *, note: str = "") -> ProtectedBlob:
    """Encrypt content under the local key and remember only its digest."""
    data = _as_bytes(plaintext)
    blob = ProtectedBlob(
        label=label,
        ciphertext=crypto.encrypt(base64.b64encode(data).decode("ascii")),
        plaintext_digest=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
    session.add(blob)
    session.commit()
    return blob


def grant(session: Session, blob_id: str, *, minutes: int = 15, note: str = "") -> AccessGrant:
    """Open a short, explicit window. The only way decryption can succeed."""
    if minutes <= 0 or minutes > 24 * 60:
        raise ValueError("a grant must last between 1 minute and 24 hours")
    record = AccessGrant(
        blob_id=blob_id,
        expires_at=_now() + dt.timedelta(minutes=minutes),
        note=note,
    )
    session.add(record)
    session.commit()
    return record


def revoke(session: Session, blob_id: str) -> int:
    live = session.scalars(
        select(AccessGrant).where(
            AccessGrant.blob_id == blob_id, AccessGrant.revoked.is_(False)
        )
    ).all()
    for row in live:
        row.revoked = True
    session.commit()
    return len(live)


def _live_grant(session: Session, blob_id: str) -> AccessGrant | None:
    now = _now()
    for row in session.scalars(
        select(AccessGrant).where(
            AccessGrant.blob_id == blob_id, AccessGrant.revoked.is_(False)
        )
    ):
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.timezone.utc)
        if expires > now:
            return row
    return None


def request(
    session: Session,
    blob_id: str,
    *,
    requester_label: str = "unidentified",
    origin_hmac: str | None = None,
    client_hash: str | None = None,
    client_family: str = "",
    client_tool: str = "",
    asn: int | None = None,
    justification: str = "",
) -> dict:
    """Ask to read a protected object. Recorded either way; denied by default.

    Returns plaintext only on a live grant. On refusal the return value carries
    the reason and the event fingerprint and no content at all.
    """
    blob = session.get(ProtectedBlob, blob_id)
    if blob is None:
        raise LookupError("no such protected object")

    live = _live_grant(session, blob_id)
    granted = live is not None
    reason = (
        "a live grant permits this read"
        if granted
        else "no live grant exists for this object, so the request is denied"
    )

    event = shadow_events.record(
        session,
        kind=shadow_events.PROTECTED_DATA_REQUEST,
        subject_ref=f"vault:{blob.id}",
        subject_kind="protected_object",
        outcome=shadow_events.GRANTED if granted else shadow_events.DENIED,
        origin_hmac=origin_hmac,
        client_hash=client_hash,
        client_family=client_family,
        client_tool=client_tool,
        asn=asn,
        detail=(
            f"{requester_label} requested '{blob.label}' "
            f"({blob.size_bytes} bytes). Outcome: "
            f"{'granted' if granted else 'denied'}. {reason}"
            + (f" Stated purpose: {justification}" if justification else "")
        ),
    )

    payload: dict = {
        "granted": granted,
        "reason": reason,
        "event_hash": event.event_hash,
        "label": blob.label,
        "plaintext": None,
    }
    if granted:
        payload["plaintext"] = base64.b64decode(crypto.decrypt(blob.ciphertext)).decode(
            "utf-8", errors="replace"
        )
    return payload


def verify_integrity(session: Session, blob_id: str) -> dict:
    """Confirm a stored blob still decrypts to the content that was locked."""
    blob = session.get(ProtectedBlob, blob_id)
    if blob is None:
        raise LookupError("no such protected object")
    try:
        raw = base64.b64decode(crypto.decrypt(blob.ciphertext))
    except Exception:
        return {"ok": False, "reason": "ciphertext does not decrypt with the local key"}
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "ok": digest == blob.plaintext_digest,
        "reason": (
            "content matches the digest recorded at lock time"
            if digest == blob.plaintext_digest
            else "content no longer matches the digest recorded at lock time"
        ),
    }

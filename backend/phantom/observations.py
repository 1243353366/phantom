"""Raw observations, stored apart from the claims derived from them.

The distinction this module enforces:

  raw observation  what arrived: headers, hosts, URLs, reasons, timestamps
  graph edge       what we concluded: a relationship, a class, a confidence

Before this module existed, the second was the only record. That worked until a
rule changed, at which point the graph held conclusions produced by a rule that
no longer exists, and the only way back was to re-read the original messages.

Layer 3 already worked the other way round: a sealed event is the raw record and
:mod:`phantom.shadow.graph` derives edges from it. This brings the mail path to
the same standard.

Nothing here stores a message body. The payload is the parse result, which is
metadata by construction, and a test asserts it stays that way.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.collector.headers import ParsedEmail
from phantom.collector.pixels import LinkObservation, PixelObservation
from phantom.models import RawObservation
from phantom.redaction import redact_ips, redact_params, safe_url

EMAIL_METADATA = "email_metadata"

#: Account exports the operator downloaded themselves. A second source, kept in
#: the same raw store so one rebuild covers both.
ACCOUNT_INVENTORY = "account_inventory"
SCHEMA_VERSION = 1

#: The complete set of keys a stored email observation may have. If a future
#: change adds a body, a rendered snippet or a recipient list, this list is where
#: the review happens.
PAYLOAD_KEYS = frozenset(
    {
        "schema",
        "message_id",
        "sent_at",
        "from_address",
        "from_domain",
        "display_name",
        "subject_hash",
        "reply_to_domains",
        "return_path_domain",
        "dkim",
        "auth_results",
        "received_hops",
        "pixels",
        "links",
        "mailer",
    }
)


def _iso(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC).isoformat()


def _minimised_pixel(pixel) -> dict:
    data = redact_ips(asdict(pixel))
    data["url"] = safe_url(data.get("url", ""))
    data["params"] = redact_params(data.get("params"))
    return data


def _minimised_link(link) -> dict:
    data = redact_ips(asdict(link))
    data["url"] = safe_url(data.get("url", ""))
    data["params"] = redact_params(data.get("params"))
    return data


def to_payload(mail: ParsedEmail) -> dict:
    """The observation as stored. No body, no rendered HTML, no recipients.

    URLs are stored without their query values and IP literals are withheld, so
    what remains is the infrastructure relationship rather than the identifier
    that personalises it. A pixel URL is still identifiable as a pixel; the
    recipient token inside it is not retained.
    """
    return {
        "schema": SCHEMA_VERSION,
        "message_id": mail.message_id,
        "sent_at": _iso(mail.sent_at),
        "from_address": mail.from_address,
        "from_domain": mail.from_domain,
        "display_name": mail.display_name,
        "subject_hash": mail.subject_hash,
        "reply_to_domains": list(mail.reply_to_domains),
        "return_path_domain": mail.return_path_domain,
        "dkim": list(mail.dkim),
        "auth_results": list(mail.auth_results),
        "received_hops": redact_ips(list(mail.received_hops)),
        "pixels": [_minimised_pixel(p) for p in mail.pixels],
        "links": [_minimised_link(link) for link in mail.links],
        "mailer": mail.mailer,
    }


def from_payload(payload: dict) -> ParsedEmail:
    """Rehydrate an observation so the current rules can be applied to it."""
    sent_at = payload.get("sent_at")
    return ParsedEmail(
        message_id=payload.get("message_id", ""),
        sent_at=dt.datetime.fromisoformat(sent_at) if sent_at else None,
        from_address=payload.get("from_address", ""),
        from_domain=payload.get("from_domain", ""),
        display_name=payload.get("display_name", ""),
        subject_hash=payload.get("subject_hash", ""),
        reply_to_domains=list(payload.get("reply_to_domains") or []),
        return_path_domain=payload.get("return_path_domain"),
        dkim=list(payload.get("dkim") or []),
        auth_results=list(payload.get("auth_results") or []),
        received_hops=list(payload.get("received_hops") or []),
        pixels=[PixelObservation(**p) for p in payload.get("pixels") or []],
        links=[LinkObservation(**link) for link in payload.get("links") or []],
        mailer=payload.get("mailer"),
    )


def digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def store(
    session: Session,
    *,
    source_kind: str,
    source_ref: str,
    payload: dict,
    observed_at: dt.datetime | None = None,
    allowed: set[str] | None = None,
) -> RawObservation:
    """Append an observation. Idempotent for the same source and content.

    ``allowed`` selects the reviewed field set for a non-email source. The guard
    exists so a new field cannot be added without deciding whether it can carry
    content, and adding a second source should not mean relaxing that for the
    first.
    """
    unknown = set(payload) - (allowed or PAYLOAD_KEYS)
    if unknown:
        raise ValueError(
            f"refusing to store unexpected observation fields: {sorted(unknown)}. "
            "Adding a field means reviewing whether it can carry message content."
        )

    payload_hash = digest(payload)
    existing = session.scalar(
        select(RawObservation).where(
            RawObservation.source_ref == source_ref,
            RawObservation.payload_hash == payload_hash,
        )
    )
    if existing is not None:
        return existing

    row = RawObservation(
        source_kind=source_kind,
        source_ref=source_ref,
        observed_at=observed_at or dt.datetime.now(dt.UTC),
        schema_version=payload.get("schema", SCHEMA_VERSION),
        payload=payload,
        payload_hash=payload_hash,
    )
    session.add(row)
    session.flush()
    return row


def load(session: Session, *, source_kind: str | None = None) -> list[RawObservation]:
    query = select(RawObservation).order_by(RawObservation.observed_at, RawObservation.id)
    if source_kind:
        query = query.where(RawObservation.source_kind == source_kind)
    return list(session.scalars(query))

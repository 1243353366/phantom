"""Recording one observable interaction.

The rule for this module is narrow on purpose: it records what arrived and
refuses to interpret it. Anything that looks like a judgement belongs in the
report, where it can carry a caveat, not in the event row.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.shadow import vault
from phantom.shadow.models import ShadowEvent

DECOY_ACCESS = "decoy_access"
PROTECTED_DATA_REQUEST = "protected_data_request"
PAYLOAD_QUARANTINED = "payload_quarantined"
INTEGRITY_CHECK = "integrity_check"

KINDS = frozenset(
    {DECOY_ACCESS, PROTECTED_DATA_REQUEST, PAYLOAD_QUARANTINED, INTEGRITY_CHECK}
)

OBSERVED = "observed"
DENIED = "denied"
GRANTED = "granted"
QUARANTINED = "quarantined"

#: Every event carries at least one innocent reading. Not decoration: an event
#: with no alternative explanation is one that has been over-read already, and
#: the recorder refuses to store it.
DEFAULT_EXPLANATIONS: dict[str, list[str]] = {
    DECOY_ACCESS: [
        "A mail-client image prefetcher loading remote content without a person deciding to.",
        "A search or archival crawler that follows every URL it can see.",
        "A security scanner run by the recipient's own organisation or provider.",
        "A link-preview generator in a chat application or ticketing system.",
        "A real person opening the document. This is the boring, common case.",
    ],
    PROTECTED_DATA_REQUEST: [
        "A misconfigured integration retrying an old credential.",
        "The owner of the data using a second device without a live grant.",
        "An automated backup or sync tool that used to be permitted.",
        "Someone with legitimate access whose grant expired unnoticed.",
    ],
    PAYLOAD_QUARANTINED: [
        "An ordinary attachment whose type the sender's client mislabelled.",
        "A legitimate archive that happens to carry an executable inside it.",
        "A signed installer from a vendor the recipient deals with.",
    ],
    INTEGRITY_CHECK: [
        "A schema migration that rewrote rows without resealing them.",
        "A restore from a partial backup.",
        "The local key was rotated, so every seal now fails to verify.",
    ],
}

#: Requested material that PHANTOM will not keep, even when it is handed over.
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+", re.I),
    re.compile(r"\b(?:api[_-]?key|token|secret|bearer)\s*[:=]\s*\S+", re.I),
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{12,}", re.I),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
]

REDACTED = "[redacted: credential material refused]"


def redact_credentials(text: str) -> tuple[str, bool]:
    """Strip anything credential-shaped before it can touch the database.

    PHANTOM never stores recovered credentials, because a credential store is a
    liability that outlives the investigation it was collected for.
    """
    found = False
    result = text or ""
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(result):
            found = True
            result = pattern.sub(REDACTED, result)
    return result, found


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


#: Bumped when the canonical form changes. A stored row records the version that
#: produced its digest, so verification can distinguish "this row was tampered
#: with" from "this row was hashed under a form I no longer compute".
FINGERPRINT_VERSION = 2

#: Every field on the row that carries meaning. The first version hashed a subset
#: (kind, subject_ref, outcome, occurred_at, origin_hmac, client_hash, asn,
#: payload_digest) and left out detail, alt_explanations, client_family,
#: client_tool, asn_org, subject_kind and credential_material_refused. That meant
#: the sentence saying what happened could be rewritten without the chain noticing,
#: which is the wrong half to leave unprotected: the narrative is the evidence.
CANONICAL_FIELDS = (
    "kind", "outcome", "occurred_at", "subject_ref", "subject_kind",
    "origin_hmac", "client_hash", "client_family", "client_tool",
    "asn", "asn_org", "detail", "alt_explanations", "payload_digest",
    "credential_material_refused",
)


def event_fingerprint(payload: dict) -> str:
    """Content-addressed id for an observation.

    Deterministic, so re-ingesting the same observation is a no-op, and any
    later edit to the stored row stops matching its own fingerprint.
    """
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def canonical_payload(event) -> dict:
    """The canonical form of a stored row, computed from the row as it is now.

    Deliberately reads the database rather than a value passed in: verification
    has to be able to disagree with what was written at the time.
    """
    payload = {}
    for name in CANONICAL_FIELDS:
        value = getattr(event, name, None)
        if name == "occurred_at" and value is not None:
            value = _aware(value).isoformat()
        payload[name] = value
    payload["fingerprint_version"] = getattr(event, "fingerprint_version", FINGERPRINT_VERSION)
    return payload


def _aware(value: dt.datetime | None) -> dt.datetime:
    if value is None:
        return dt.datetime.now(dt.UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)


def record(
    session: Session,
    *,
    kind: str,
    subject_ref: str,
    outcome: str = OBSERVED,
    subject_kind: str = "protected_object",
    occurred_at: dt.datetime | None = None,
    origin_hmac: str | None = None,
    client_hash: str | None = None,
    client_family: str = "",
    client_tool: str = "",
    asn: int | None = None,
    asn_org: str | None = None,
    detail: str = "",
    alt_explanations: list[str] | None = None,
    payload_digest: str | None = None,
) -> ShadowEvent:
    if kind not in KINDS:
        raise ValueError(f"unknown shadow event kind: {kind}")
    if alt_explanations is not None and not alt_explanations:
        raise ValueError(
            "an event with no alternative explanation has already been over-read; "
            "supply at least one"
        )
    explanations = list(alt_explanations or DEFAULT_EXPLANATIONS[kind])
    at = _aware(occurred_at)
    clean_detail, refused = redact_credentials(detail)

    fingerprint = event_fingerprint(
        {
            "kind": kind,
            "outcome": outcome,
            "occurred_at": at.isoformat(),
            "subject_ref": subject_ref,
            "subject_kind": subject_kind,
            "origin_hmac": origin_hmac,
            "client_hash": client_hash,
            "client_family": client_family,
            "client_tool": client_tool,
            "asn": asn,
            "asn_org": asn_org,
            "detail": clean_detail,
            "alt_explanations": explanations,
            "payload_digest": payload_digest,
            "credential_material_refused": refused,
            "fingerprint_version": FINGERPRINT_VERSION,
        }
    )

    existing = session.scalar(select(ShadowEvent).where(ShadowEvent.event_hash == fingerprint))
    if existing is not None:
        return existing

    event = ShadowEvent(
        event_hash=fingerprint,
        kind=kind,
        outcome=outcome,
        occurred_at=at,
        subject_ref=subject_ref,
        subject_kind=subject_kind,
        origin_hmac=origin_hmac,
        client_hash=client_hash,
        client_family=client_family,
        client_tool=client_tool,
        asn=asn,
        asn_org=asn_org,
        detail=clean_detail,
        alt_explanations=explanations,
        payload_digest=payload_digest,
        credential_material_refused=refused,
        fingerprint_version=FINGERPRINT_VERSION,
    )
    session.add(event)
    session.flush()

    link = vault.append(
        session,
        event_hash=fingerprint,
        kind=kind,
        subject_ref=subject_ref,
        occurred_at=at,
    )
    event.vault_seq = link.seq
    session.commit()
    return event

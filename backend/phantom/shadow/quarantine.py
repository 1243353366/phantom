"""Payload quarantine: keep the evidence, never the risk.

A quarantined payload is stored encrypted, described by a digest and a magic-byte
guess, and never executed, unpacked or rendered. That is the whole feature. It
exists because "we kept the sample" is the difference between a credible record
and a story, and because the sample itself must not become the incident.
"""
from __future__ import annotations

import base64
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom import crypto
from phantom.shadow import events as shadow_events
from phantom.shadow.models import QuarantinedPayload

#: First bytes are enough to say what a file claims to be. Deliberately shallow:
#: anything deeper is parsing attacker-controlled data for fun.
MAGIC: list[tuple[bytes, str]] = [
    (b"MZ", "windows-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"\xca\xfe\xba\xbe", "macho-executable"),
    (b"PK\x03\x04", "zip-archive"),
    (b"%PDF", "pdf-document"),
    (b"\xd0\xcf\x11\xe0", "ole-document"),
    (b"Rar!", "rar-archive"),
    (b"\x1f\x8b", "gzip-archive"),
    (b"<script", "html-with-script"),
    (b"<!DOCTYPE html", "html"),
]

EXECUTABLE_TYPES = frozenset(
    {"windows-executable", "elf-executable", "macho-executable"}
)


def sniff(payload: bytes) -> tuple[str, bool]:
    if payload[:4] == b"PK\x03\x04" and b"vbaProject" in payload[:65536]:
        return "office-document-with-macros", True
    for magic, name in MAGIC:
        if payload.startswith(magic):
            return name, name in EXECUTABLE_TYPES
    head = payload[:512].lstrip().lower()
    if head.startswith(b"<html") or head.startswith(b"<script"):
        return "html", False
    return "unrecognised", False


def capture(
    session: Session,
    payload: bytes,
    *,
    source_ref: str,
    declared_type: str = "",
    origin_hmac: str | None = None,
    client_hash: str | None = None,
    client_family: str = "",
    client_tool: str = "",
    asn: int | None = None,
) -> dict:
    """Store a suspicious payload, encrypted, and record one event about it."""
    digest = hashlib.sha256(payload).hexdigest()
    existing = session.scalar(
        select(QuarantinedPayload).where(QuarantinedPayload.digest == digest)
    )
    sniffed, executable = sniff(payload)
    if existing is None:
        existing = QuarantinedPayload(
            digest=digest,
            ciphertext=crypto.encrypt(base64.b64encode(payload).decode("ascii")),
            size_bytes=len(payload),
            declared_type=declared_type,
            sniffed_type=sniffed,
            executable_signature=executable,
            source_ref=source_ref,
        )
        session.add(existing)
        session.commit()

    event = shadow_events.record(
        session,
        kind=shadow_events.PAYLOAD_QUARANTINED,
        subject_ref=f"payload:{digest[:16]}",
        subject_kind="payload",
        outcome=shadow_events.QUARANTINED,
        origin_hmac=origin_hmac,
        client_hash=client_hash,
        client_family=client_family,
        client_tool=client_tool,
        asn=asn,
        payload_digest=digest,
        detail=(
            f"Payload of {len(payload)} bytes from {source_ref or 'unknown source'} "
            f"was stored encrypted. Declared type: {declared_type or 'none'}. "
            f"Sniffed type: {sniffed}"
            + (" (executable signature present)" if executable else "")
            + ". Not executed, not unpacked, not rendered."
        ),
    )

    return {
        "digest": digest,
        "size_bytes": len(payload),
        "sniffed_type": sniffed,
        "executable_signature": executable,
        "executed": False,
        "event_hash": event.event_hash,
        "note": (
            "Stored for evidence only. The sample is encrypted at rest and is never "
            "opened by PHANTOM."
        ),
    }

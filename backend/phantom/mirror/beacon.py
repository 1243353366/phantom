"""The canary endpoint.

Serves a 1x1 GIF, records what the request volunteered, and nothing else.

Design constraints, each of which is a test:

* No outbound call. Serving a canary must never itself become a beacon, which
  would make PHANTOM a participant in the ecosystem it maps.
* Bounded tarpit. A hold is capped and off by default, so a honeypot cannot be
  turned into a resource-exhaustion weapon against the person running it.
* The GIF is always returned, whatever the client looks like. Refusing to answer
  tells a prober that it was detected, and detection is the one piece of
  information a collector would pay to have.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.config import settings
from phantom.mirror import tokens
from phantom.mirror.fingerprint import AttemptFingerprint, fingerprint
from phantom.mirror.models import MirrorObservation

#: Smallest valid 1x1 transparent GIF (43 bytes). No cache headers are set by the
#: handler, so a repeat fetch happens and becomes a second data point.
TRANSPARENT_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!"
    b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
    b"\x00\x02\x02D\x01\x00;"
)

#: Even if configured higher, never hold a request longer than this.
TARPIT_HARD_CAP_MS = 2000


class UnknownCanary(LookupError):
    """Token did not resolve. The caller should still return the GIF."""


def tarpit_delay_ms(fp: AttemptFingerprint) -> int:
    """Bounded, signal-driven hold. Slows naive walkers, never weaponises us."""
    configured = min(max(settings.tarpit_ms_max, 0), TARPIT_HARD_CAP_MS)
    if configured == 0 or not fp.looks_automated:
        return 0
    weight = sum(s["weight"] for s in fp.extraction_signals)
    return min(configured, 250 * weight)


def record_observation(
    session: Session,
    *,
    token: str,
    source_ip: str,
    headers: dict[str, str],
    method: str = "GET",
    path: str = "",
    received_at: dt.datetime | None = None,
    asn_db: Path | None = None,
) -> tuple[MirrorObservation, int]:
    """Persist one hit. Returns the stored observation and the tarpit delay."""
    row = tokens.verify(session, token)
    if row is None:
        raise UnknownCanary("token did not resolve")

    fp = fingerprint(
        source_ip=source_ip, headers=headers, method=method, path=path, asn_db=asn_db
    )
    delay = tarpit_delay_ms(fp)

    observation = MirrorObservation(
        token_id=row.id,
        received_at=received_at or dt.datetime.now(dt.UTC),
        origin_hmac=fp.origin_hmac,
        origin_raw=fp.origin_raw,
        asn=fp.asn,
        asn_org=fp.asn_org,
        client_hash=fp.client_hash,
        client_family=fp.client_family,
        client_tool=fp.client_tool,
        extraction_signals=fp.extraction_signals,
        headers=fp.headers,
        path=path[:400],
        method=method.upper()[:8],
        tarpit_ms=delay,
    )
    session.add(observation)
    session.commit()
    return observation, delay


def observations_for(session: Session, token: str) -> list[MirrorObservation]:
    row = tokens.verify(session, token)
    if row is None:
        return []
    return list(
        session.scalars(
            select(MirrorObservation)
            .where(MirrorObservation.token_id == row.id)
            .order_by(MirrorObservation.received_at)
        )
    )


def purge_expired(session: Session) -> int:
    """Retention. Canary hits are the most sensitive rows PHANTOM holds."""
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=settings.mirror_retention_days)
    stale = [
        row
        for row in session.scalars(select(MirrorObservation))
        if (row.received_at if row.received_at.tzinfo else row.received_at.replace(tzinfo=dt.UTC)) < cutoff
    ]
    for row in stale:
        session.delete(row)
    session.commit()
    return len(stale)

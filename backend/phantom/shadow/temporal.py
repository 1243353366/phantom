"""Temporal proximity between adversarial events.

Two protected objects reached by one indicator inside a window is worth knowing.
It is also exactly what an automated collector produces all day long, so every
candidate here is a hypothesis with a ceiling and at least three innocent
readings attached.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.engine.classify import HYPOTHESIZED, confidence_for
from phantom.shadow.models import ShadowEvent

CO_OCCURRENCE_EXPLANATIONS = [
    "A crawler working through a directory of links in order.",
    "A backup or archival job that touches many objects at once.",
    "A mail-security or DLP scanner sweeping an entire mailbox.",
    "A shared egress that carries unrelated traffic from different parties.",
    "One person legitimately opening several related documents in one sitting.",
]

#: A ceiling, not a target. Proximity in time on its own cannot support more.
CEILING_BASE = 0.35


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def co_occurrences(
    session: Session, *, window_minutes: int = 60, limit: int = 50
) -> list[dict]:
    events = session.scalars(
        select(ShadowEvent).order_by(ShadowEvent.occurred_at)
    ).all()
    if len(events) < 2:
        return []

    window = dt.timedelta(minutes=window_minutes)
    groups: dict[str, list[ShadowEvent]] = defaultdict(list)
    for event in events:
        if event.origin_hmac:
            groups[f"origin:{event.origin_hmac[:16]}"].append(event)
        if event.client_hash:
            groups[f"client_stack:{event.client_hash[:16]}"].append(event)

    results: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for indicator, group in groups.items():
        ordered = sorted(group, key=lambda e: _aware(e.occurred_at))
        for i, first in enumerate(ordered):
            for second in ordered[i + 1:]:
                gap = _aware(second.occurred_at) - _aware(first.occurred_at)
                if gap > window:
                    break
                if first.subject_ref == second.subject_ref:
                    continue
                a, b = sorted((first.subject_ref, second.subject_ref))
                key = (indicator, a, b)
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    {
                        "indicator": indicator,
                        "subjects": [a, b],
                        "gap_minutes": round(gap.total_seconds() / 60, 2),
                        "window_minutes": window_minutes,
                        "first_at": _aware(first.occurred_at).isoformat(),
                        "last_at": _aware(second.occurred_at).isoformat(),
                        "classification": HYPOTHESIZED,
                        # One co-occurrence is one observation. Repetition raises
                        # confidence towards the hypothesis ceiling and no further.
                        "confidence": confidence_for(HYPOTHESIZED, 1, CEILING_BASE),
                        "alternative_explanations": CO_OCCURRENCE_EXPLANATIONS,
                        "caveat": (
                            "Two objects reached inside one window by one observable "
                            "indicator. This is a lead, not a link, and automated "
                            "collection produces it constantly."
                        ),
                    }
                )
                if len(results) >= limit:
                    return results
    return results

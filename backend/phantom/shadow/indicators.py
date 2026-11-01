"""Recurring indicators across adversarial events.

An indicator is an observable: a hashed origin, a client stack, a network. When
it recurs, that is a fact about infrastructure, and it is the only kind of
"linking" Layer 3 is allowed to do on its own.

The module deliberately returns counts and alternative readings side by side, so
a consumer has to pass the alternative to reach the count.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.shadow.models import ShadowEvent

INDICATOR_EXPLANATIONS = [
    "A shared network egress: carrier NAT, corporate proxy, cloud region, VPN exit.",
    "A shared collection tool. The same library in two unrelated products looks identical.",
    "One organisation's own repeated automated checks against its own data.",
    "A CDN or mail-security vendor scanning on behalf of many customers.",
    "A researcher or journalist working a story, which is legitimate and common.",
]


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _bucket(events: list[ShadowEvent], kind: str, extract) -> list[dict]:
    groups: dict[str, list[ShadowEvent]] = defaultdict(list)
    for event in events:
        value = extract(event)
        if value in (None, "", 0):
            continue
        groups[str(value)].append(event)

    out = []
    for value, group in groups.items():
        ordered = sorted(group, key=lambda e: _aware(e.occurred_at))
        subjects = sorted({e.subject_ref for e in ordered})
        out.append(
            {
                "indicator_type": kind,
                "indicator": value[:16],
                "events": len(ordered),
                "distinct_subjects": len(subjects),
                "subjects": subjects,
                "kinds": sorted({e.kind for e in ordered}),
                "outcomes": sorted({e.outcome for e in ordered}),
                "first_seen": _aware(ordered[0].occurred_at).isoformat(),
                "last_seen": _aware(ordered[-1].occurred_at).isoformat(),
                "alternative_explanations": INDICATOR_EXPLANATIONS,
                "caveat": (
                    "Recurrence is a property of the observable, not of a person. "
                    "Nothing here distinguishes one actor from a shared address."
                ),
            }
        )
    return sorted(out, key=lambda row: (-row["events"], row["indicator_type"]))


def recurring(session: Session, *, min_events: int = 2) -> list[dict]:
    events = session.scalars(select(ShadowEvent)).all()
    rows = (
        _bucket(events, "origin", lambda e: e.origin_hmac)
        + _bucket(events, "client_stack", lambda e: e.client_hash)
        + _bucket(events, "network", lambda e: e.asn)
    )
    return [row for row in rows if row["events"] >= min_events]

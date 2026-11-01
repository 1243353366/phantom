"""The Layer 3 report.

Written to be read by someone deciding whether to believe it. Counts first, then
the innocent readings, then what the layer explicitly cannot tell you.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.engine.classify import CROSS_LAYER_RULES, RULES
from phantom.shadow import bridges, indicators, temporal, vault
from phantom.shadow.models import BridgeProposal, QuarantinedPayload, ShadowEvent


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def adversarial_report(session: Session) -> dict:
    events = session.scalars(
        select(ShadowEvent).order_by(ShadowEvent.occurred_at)
    ).all()
    proposals = session.scalars(select(BridgeProposal)).all()
    payloads = session.scalars(select(QuarantinedPayload)).all()
    chain = vault.verify(session)

    by_kind = Counter(e.kind for e in events)
    by_outcome = Counter(e.outcome for e in events)

    subjects: dict[str, dict] = {}
    for event in events:
        bucket = subjects.setdefault(
            event.subject_ref,
            {"subject": event.subject_ref, "events": 0, "kinds": set(),
             "outcomes": set(), "first_at": _aware(event.occurred_at)},
        )
        bucket["events"] += 1
        bucket["kinds"].add(event.kind)
        bucket["outcomes"].add(event.outcome)
        bucket["first_at"] = min(bucket["first_at"], _aware(event.occurred_at))

    touched = sorted(
        (
            {
                "subject": row["subject"],
                "events": row["events"],
                "kinds": sorted(row["kinds"]),
                "outcomes": sorted(row["outcomes"]),
                "first_at": row["first_at"].isoformat(),
            }
            for row in subjects.values()
        ),
        key=lambda row: row["first_at"],
    )

    pending = [p for p in proposals if p.status == "proposed"]
    confirmed = [p for p in proposals if p.status == "confirmed"]
    rejected = [p for p in proposals if p.status == "rejected"]

    refusal_note = None
    if events:
        refusal_note = (
            f"{by_outcome.get('denied', 0)} request(s) for protected data were "
            "recorded and refused, and a refusal is not an accusation: an expired "
            "grant and a hostile probe produce the same row."
        )

    return {
        "layer": "adversarial",
        "events": len(events),
        "by_kind": dict(by_kind),
        "by_outcome": dict(by_outcome),
        "protected_objects_touched": touched,
        "recurring_indicators": indicators.recurring(session),
        "co_occurrence_candidates": temporal.co_occurrences(session),
        "quarantined_payloads": [
            {
                "digest": p.digest,
                "size_bytes": p.size_bytes,
                "declared_type": p.declared_type,
                "sniffed_type": p.sniffed_type,
                "executable_signature": p.executable_signature,
                "source_ref": p.source_ref,
            }
            for p in payloads
        ],
        "bridges": {
            "pending": [bridges.serialize(p) for p in pending],
            "confirmed": [bridges.serialize(p) for p in confirmed],
            "rejected": [bridges.serialize(p) for p in rejected],
            "note": (
                "A confirmed bridge is the weakest edge in the graph and the only "
                "way the layers join. Confirming one is a judgement call, and it is "
                "reversible by rejecting a fresh proposal."
            ),
        },
        "vault": chain,
        "refusal_note": refusal_note,
        "guardrails": guardrails(),
        "cannot_tell_you": [
            "Who any of these observables belong to. There is no identity at any node.",
            "Whether an attempt was hostile. Intent is not observable at this layer.",
            "Whether two events share an operator, as opposed to a network or a tool.",
            "Anything about a third party's systems. Layer 3 only records what "
            "arrived at yours.",
        ],
        "layers": {
            "surveillance": "Who is positioned to observe you: senders, providers, trackers.",
            "relationship": "Who you actually communicate with, processed locally only.",
            "adversarial": "What interacted with your protective infrastructure.",
            "separation_rule": (
                "Layers 1-2 and Layer 3 are distinct node namespaces. The engine "
                "refuses cross-layer edges during ingestion; only a confirmed "
                f"bridge can create one ({', '.join(sorted(CROSS_LAYER_RULES))})."
            ),
        },
    }


def guardrails() -> dict:
    return {
        "active_probing_of_third_parties": False,
        "outbound_requests_to_requester": 0,
        "retaliation_enabled": False,
        "recovered_credentials_stored": False,
        "quarantined_payloads_executed": False,
        "automatic_layer_merges": 0,
        "raw_source_addresses_retained_by_default": False,
        "identity_fields_collected": "none",
        "why": (
            "Every capability here is passive. Probing a third party would make "
            "PHANTOM an active participant, retaliation would make it an attacker, "
            "and storing recovered credentials would create a liability that "
            "outlives the investigation."
        ),
    }


def rule_catalogue() -> list[dict]:
    return [
        {
            "id": rule.id,
            "classification": rule.classification,
            "relation": rule.relation,
            "description": rule.description,
            "caveat": rule.caveat,
            "requires_human_confirmation": rule.requires_confirmation,
        }
        for rule in RULES.values()
        if rule.id.startswith("R-SHD-")
    ]

"""What an extraction attempt revealed about itself.

This is the whole point of the mechanism, stated as plainly as possible: the
asymmetry is not that you hit back, it is that the attempt was not free. A
collector that fetches a canary learns nothing it wanted, and in exchange hands
over its network origin, its tooling, its timing, and which of your copies it
holds.

Every claim here is bounded by what was actually observed. No identities, no
attribution to an organisation unless that organisation is literally the ASN
holder in a local table, and never a guess about a person.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.config import settings
from phantom.mirror import tokens
from phantom.mirror.beacon import TARPIT_HARD_CAP_MS
from phantom.mirror.countergraph import BURST_WINDOW_MIN, bursts
from phantom.mirror.models import CanaryToken, MirrorObservation


def asymmetry_report(session: Session) -> dict:
    rows = session.execute(
        select(MirrorObservation, CanaryToken).join(
            CanaryToken, MirrorObservation.token_id == CanaryToken.id
        )
    ).all()

    if not rows:
        return {
            "canaries": session.query(CanaryToken).count(),
            "hits": 0,
            "summary": "No canary has been touched yet.",
            "what_they_learned": [],
            "what_you_learned": [],
            "leaked_copies": [],
            "campaigns": [],
            "guardrails": _guardrails(),
        }

    origins = {o.origin_hmac for o, _ in rows}
    clients = {o.client_hash for o, _ in rows}
    asns = {o.asn for o, _ in rows if o.asn is not None}
    automated = [o for o, _ in rows if o.extraction_signals]

    per_label: dict[str, dict] = {}
    for obs, canary in rows:
        bucket = per_label.setdefault(
            canary.label,
            {
                "label": canary.label,
                "token": tokens.token_fingerprint(canary.token),
                "hits": 0,
                "first": obs.received_at,
                "clients": set(),
            },
        )
        bucket["hits"] += 1
        bucket["first"] = min(bucket["first"], obs.received_at)
        bucket["clients"].add(obs.client_family)

    leaked = sorted(
        (
            {
                "label": v["label"],
                "token": v["token"],
                "hits": v["hits"],
                "first_seen": v["first"].isoformat(),
                "client_families": sorted(v["clients"]),
            }
            for v in per_label.values()
        ),
        key=lambda r: r["first_seen"],
    )

    # Campaigns: which canaries were hit by the same client stack.
    canaries_by_client: dict[str, set[str]] = defaultdict(set)
    for obs, canary in rows:
        canaries_by_client[obs.client_hash].add(canary.label)
    campaigns = [
        {
            "client_family": next(
                (o.client_family for o, _ in rows if o.client_hash == ch), "unknown"
            ),
            "canaries_touched": sorted(labels),
            "classification": "hypothesized",
            "caveat": (
                "Grouped by shared tooling. A widely used crawler will cluster "
                "everything it touches, and this is not proof of a common operator."
            ),
        }
        for ch, labels in canaries_by_client.items()
        if len(labels) > 1
    ]

    signal_counts = Counter(s["signal"] for o in automated for s in o.extraction_signals)

    return {
        "canaries": session.query(CanaryToken).count(),
        "hits": len(rows),
        "distinct_origins": len(origins),
        "distinct_clients": len(clients),
        "distinct_networks": len(asns),
        "automated_hits": len(automated),
        "summary": (
            f"{len(rows)} canary fetch(es) from {len(origins)} origin(s) using "
            f"{len(clients)} client stack(s) across {len(asns)} known network(s)."
        ),
        "what_they_learned": [
            "That a URL resolved and returned an image. Nothing about you.",
            "Nothing about which document the canary sat in: the token is opaque.",
        ],
        "what_you_learned": [
            f"Which {len(leaked)} of your copies were extracted, by label.",
            f"The network origin of each fetch (pseudonymous HMAC by default, "
            f"raw address retained: {'yes' if settings.retain_raw_ip else 'no'}).",
            "The client stack and whether it looked automated, with the signals that "
            "led to that conclusion.",
            "Timing and burst structure, so you can tell one enthusiastic scanner "
            "from a repeated collection run.",
            f"Which canaries cluster together into a likely campaign "
            f"({len(campaigns)} cluster(s), hypothesized only).",
        ],
        "leaked_copies": leaked,
        "campaigns": campaigns,
        "episodes": bursts(session),
        "signal_counts": dict(signal_counts),
        "relations_used": {
            "observed": "A request that actually arrived at a canary.",
            "correlated": "Same client stack from distinct origins on one network.",
            "hypothesized": "Canaries grouped by shared tooling.",
        },
        "guardrails": _guardrails(),
        "caveats": [
            "An access is not an identity. Anyone can send a request with any user agent.",
            "A shared network is not a shared actor: cloud regions and proxy pools "
            "host unrelated traffic.",
            "Behind a proxy chain the observed origin is the proxy, not the requester.",
            "If the canary is published publicly, a search-engine crawler will fetch "
            "it, and that is not an attack.",
        ],
    }


def _guardrails() -> dict:
    return {
        "retaliation_enabled": False,
        "outbound_requests_made_to_requester": 0,
        "exploitation_attempted": False,
        "tarpit_cap_ms": min(settings.tarpit_ms_max, TARPIT_HARD_CAP_MS),
        "tarpit_note": (
            "A bounded delay only. Never a hold long enough to be a weapon, and "
            "never conditioned on the requester staying connected."
        ),
        "raw_ip_retained": settings.retain_raw_ip,
        "retention_days": settings.mirror_retention_days,
        "burst_window_minutes": BURST_WINDOW_MIN,
        "identifier_collected": "none. No cookie is set, no JavaScript is used, "
                                "no fingerprint beyond the request's own headers.",
        "why": (
            "Hacking back is illegal in most jurisdictions, attacks whoever owns "
            "the host actually making the request, and would make this tool the "
            "surveillance layer it exists to reveal."
        ),
    }

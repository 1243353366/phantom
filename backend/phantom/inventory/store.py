"""Turn a reading into an observation, and a stored observation into a graph.

An own-account inventory is a *source of observations*, exactly like message
metadata, so it flows through the same raw/derived split. That matters: it means
`phantom rebuild-graph` re-derives the inventory graph from what was recorded
rather than trusting rows written last time a rule was different.

Nothing reversible is stored. Email, phone and account id are kept as keyed
HMACs, so the same value can be recognised again without the database holding a
contactable address for anyone.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from phantom import observations
from phantom.crypto import hmac_hex
from phantom.inventory.facets import Facet, Reading

#: Payload fields an inventory observation may carry. Reviewed as a separate
#: allowlist so the email observation schema cannot quietly absorb account data.
INVENTORY_PAYLOAD_KEYS = {
    "schema",
    "kind",
    "platform",
    "handle",
    "identifiers",
    "source_fields",
    "files_read",
}

KIND = "account_inventory"


def _identifier_hmac(facet: Facet) -> dict:
    return {
        "kind": facet.kind,
        "hmac": hmac_hex(facet.normalised, domain=f"inventory:{facet.kind}"),
    }


def to_payload(reading: Reading) -> dict:
    """Build the storable payload. Contact values never appear in it."""
    handles = [f for f in reading.facets if f.kind == "handle"]
    identifiers = [_identifier_hmac(f) for f in reading.facets if f.kind != "handle"]
    # De-duplicate: the same email at two paths is one fact.
    seen: set[tuple[str, str]] = set()
    unique = []
    for identifier in identifiers:
        key = (identifier["kind"], identifier["hmac"])
        if key not in seen:
            seen.add(key)
            unique.append(identifier)

    return {
        "schema": 1,
        "kind": KIND,
        "platform": reading.platform,
        "handle": handles[0].normalised if handles else "",
        "identifiers": unique,
        "source_fields": sorted({f.source_field for f in reading.facets}),
        "files_read": sorted(reading.files_read),
    }


def record(
    session: Session,
    reading: Reading,
    *,
    source_ref: str | None = None,
    observed_at: dt.datetime | None = None,
):
    payload = to_payload(reading)
    label = payload["handle"] or payload["identifiers"][0]["hmac"][:12]
    reference = source_ref or f"inventory:{reading.platform}:{label}"
    return observations.store(
        session,
        source_kind=observations.ACCOUNT_INVENTORY,
        source_ref=reference,
        payload=payload,
        observed_at=observed_at,
        allowed=INVENTORY_PAYLOAD_KEYS,
    )


def project(session: Session) -> dict:
    """Derive presence and identifier nodes for every stored inventory row."""
    from phantom.engine.relationship_engine import RelationshipEngine

    engine = RelationshipEngine(session)
    stored = observations.load(session, source_kind=observations.ACCOUNT_INVENTORY)

    created = {"presences": 0, "identifiers": 0, "uses_identifier": 0, "shares_handle": 0}
    presences: dict[str, dict] = {}

    for row in stored:
        payload = row.payload
        platform = payload.get("platform") or "unknown"
        handle = payload.get("handle") or ""
        if not handle:
            # An account with no handle has nothing to correlate. Its identifiers
            # are still recorded, under an anonymous presence key.
            handle = f"unnamed-{row.id}"

        presence_key = f"presence:{platform}:{handle}"
        engine._node(
            presence_key,
            "presence",
            f"{handle} ({platform})",
            {
                "platform": platform,
                "handle": handle,
                "source_fields": payload.get("source_fields", []),
                "files_read": payload.get("files_read", []),
            },
        )
        created["presences"] += 1
        presences[presence_key] = {"platform": platform, "handle": handle}

        for identifier in payload.get("identifiers", []):
            id_key = f"identifier:{identifier['kind']}:{identifier['hmac'][:24]}"
            engine._node(
                id_key,
                "identifier",
                f"{identifier['kind']} (withheld)",
                {"kind": identifier["kind"]},
            )
            created["identifiers"] += 1
            engine._edge(
                "R-INV-1",
                presence_key,
                id_key,
                evidence_kind="account_export",
                detail=(
                    f"The operator's own {platform} export listed a "
                    f"{identifier['kind']} on this account. Stored as a keyed "
                    "digest, so the value can be recognised but not read back."
                ),
                source_ref=f"{row.source_ref}:{identifier['kind']}",
                payload={"identifier_kind": identifier["kind"], "platform": platform},
                base_confidence=0.9,
            )
            created["uses_identifier"] += 1

    # Same handle string on two platforms. Deliberately a correlated claim, not
    # an observed one: identical strings are not a verified identity.
    ordered = sorted(presences.items())
    for i, (key_a, a) in enumerate(ordered):
        for key_b, b in ordered[i + 1:]:
            if a["platform"] == b["platform"] or a["handle"] != b["handle"]:
                continue
            engine._edge(
                "R-INV-2",
                key_a,
                key_b,
                evidence_kind="handle_reuse",
                detail=(
                    f"Both of the operator's accounts use the handle '{a['handle']}' "
                    f"({a['platform']} and {b['platform']}). Identical strings are "
                    "a correlation, not a verified identity: anyone may reuse a "
                    "handle, and variants such as separators are not linked here."
                ),
                source_ref=f"inv2:{a['handle']}:{a['platform']}:{b['platform']}",
                base_confidence=0.5,
            )
            created["shares_handle"] += 1

    session.flush()
    return created

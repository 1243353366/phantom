"""Contact analysis must not become the surveillance database it warns about."""
from __future__ import annotations

import json

from phantom.collector.headers import parse_eml
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.exposure.local_contacts import ContactExposureAnalyzer, parse_csv

CSV = """name,email,phone
Alice,billing@acme-store.com,
Bob,bob@northwind-supply.com,
Carol,carol@unrelated-personal.example,
Dave,,+1 555 123 4567
"""


def test_parser_keeps_only_domain_and_a_phone_boolean():
    records = parse_csv(CSV)
    assert len(records) == 4
    for record in records:
        assert not hasattr(record, "email") or getattr(record, "email", None) is None
        assert record.email_domain is None or "@" not in record.email_domain
    assert any(r.has_phone for r in records)


def test_intersections_are_domains_not_people(session, sample_paths):
    engine = RelationshipEngine(session)
    for path in sample_paths:
        engine.ingest(parse_eml(path.read_bytes()), source_ref=f"eml:{path.name}")
    engine.correlate()

    result = ContactExposureAnalyzer(session).analyze_csv(CSV)
    payload = json.dumps(result.as_dict())
    assert "billing@acme-store.com" not in payload
    assert "Alice" not in payload
    assert "+1 555 123 4567" not in payload
    assert any(i["domain"] == "acme-store.com" for i in result.intersections)


def test_exclusions_are_honoured(session, sample_paths):
    engine = RelationshipEngine(session)
    for path in sample_paths:
        engine.ingest(parse_eml(path.read_bytes()), source_ref=f"eml:{path.name}")

    result = ContactExposureAnalyzer(session).analyze_csv(
        CSV, exclude_domains={"acme-store.com"}
    )
    assert not any(i["domain"] == "acme-store.com" for i in result.intersections)
    assert result.excluded.get("user excluded") == 1


def test_result_carries_the_distinction_between_kinds_of_relationship(session):
    result = ContactExposureAnalyzer(session).analyze_csv(CSV)
    payload = result.as_dict()
    assert set(payload["relation_kinds"]) >= {
        "contact_record", "technical_relationship",
        "communication_relationship", "speculative_association",
    }
    assert any("No contact left it" in note for note in payload["notes"])

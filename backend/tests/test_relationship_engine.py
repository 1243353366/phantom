"""The promise under test: no edge without provenance, and no overclaiming."""
from __future__ import annotations

from sqlalchemy import select

from phantom.collector.headers import parse_eml
from phantom.config import settings
from phantom.engine.relationship_engine import RelationshipEngine, normalize_identity
from phantom.models import Edge, Node


def ingest_all(session, sample_paths):
    engine = RelationshipEngine(session)
    for path in sample_paths:
        engine.ingest(parse_eml(path.read_bytes()), source_ref=f"eml:{path.name}")
    engine.correlate()
    return engine


def test_every_edge_has_evidence(session, sample_paths):
    ingest_all(session, sample_paths)
    for edge in session.scalars(select(Edge)):
        assert edge.evidence, f"edge {edge.rule_id} {edge.src_key}->{edge.dst_key} has no evidence"


def test_sender_links_to_provider_with_registry_provenance(session, sample_paths):
    ingest_all(session, sample_paths)
    edge = session.scalar(
        select(Edge).where(
            Edge.src_key == "org:domain:acme-store.com",
            Edge.dst_key == "provider:Mailchimp",
        )
    )
    assert edge is not None
    assert edge.classification == "observed"
    assert any("list-manage.com" in e.detail for e in edge.evidence)


def test_correlation_needs_independent_observations(session, sample_paths):
    ingest_all(session, sample_paths)
    correlated = list(session.scalars(select(Edge).where(Edge.classification == "correlated")))
    assert correlated, "two senders sharing Mailchimp should produce a correlated edge"
    for edge in correlated:
        assert edge.observation_count >= settings.correlation_threshold or edge.rule_id == "R-COR-1"
        assert edge.caveat and "does not establish common ownership" in edge.caveat


def test_hypothesized_confidence_is_capped(session, sample_paths):
    ingest_all(session, sample_paths)
    hyp = list(session.scalars(select(Edge).where(Edge.classification == "hypothesized")))
    assert hyp, "the rebrand fixture should raise an identity-continuity hypothesis"
    for edge in hyp:
        assert edge.confidence <= 0.65
        assert edge.caveat


def test_ingest_is_idempotent_per_message(session, sample_paths):
    engine = RelationshipEngine(session)
    path = sample_paths[0]
    mail = parse_eml(path.read_bytes())
    engine.ingest(mail, source_ref="eml:same")
    engine.ingest(mail, source_ref="eml:same")
    edge = session.scalar(
        select(Edge).where(Edge.dst_key == "provider:Mailchimp", Edge.rule_id == "R-OBS-2")
    )
    assert edge.observation_count == 1
    assert len(edge.evidence) == 1


def test_relay_edges_carry_a_weak_evidence_caveat(session, sample_paths):
    ingest_all(session, sample_paths)
    relay = session.scalar(select(Edge).where(Edge.rule_id == "R-OBS-3"))
    assert relay is not None
    assert "relay" in relay.caveat.lower()


def test_unattributed_domains_are_reported_not_guessed(session, sample_paths):
    engine = ingest_all(session, sample_paths)
    gaps = engine.unresolved()
    # klaviyo.com appears only as a redirect landing host and is not in the
    # registry, so it must be reported as a gap rather than labelled.
    assert "klaviyo.com" in gaps["unattributed_domains"]
    # A domain absent from the registry must not have been assigned a provider.
    assert not session.scalar(
        select(Node).where(Node.key == "provider:acme-store.com")
    )


def test_identity_normalisation_strips_legal_suffixes():
    assert normalize_identity("Acme Store, Inc.") == "acme store"

"""Raw observations, and the graph that is derived from them.

The property under test: the claims in the graph can be thrown away and
re-derived from what was observed, without losing anything that was not a claim.
"""
from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from phantom import observations, rebuild
from phantom.collector.headers import parse_eml
from phantom.engine import classify
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.models import Edge, Node, RawObservation
from phantom.shadow import bridges, vault
from phantom.shadow import events as shadow_events
from phantom.shadow import graph as shadow_graph
from phantom.shadow.models import BridgeProposal, ShadowEvent


def _ingest(session, path, source_ref):
    return RelationshipEngine(session).ingest(parse_eml(path.read_bytes()), source_ref=source_ref)


# --- what is stored ----------------------------------------------------
def test_ingest_stores_the_observation_before_concluding_anything(session, sample_paths):
    _ingest(session, sample_paths[0], "eml:one")
    rows = session.scalars(select(RawObservation)).all()
    assert len(rows) == 1
    assert len(rows[0].payload_hash) == 64
    assert rows[0].source_kind == observations.EMAIL_METADATA


def test_the_same_message_twice_is_one_observation(session, sample_paths):
    _ingest(session, sample_paths[0], "eml:one")
    _ingest(session, sample_paths[0], "eml:one")
    assert len(session.scalars(select(RawObservation)).all()) == 1


def test_a_second_distinct_observation_appends_rather_than_replacing(session, sample_paths):
    _ingest(session, sample_paths[0], "eml:one")
    _ingest(session, sample_paths[1], "eml:two")
    assert len(session.scalars(select(RawObservation)).all()) == 2


def test_payload_is_metadata_only(session, sample_paths):
    _ingest(session, sample_paths[0], "eml:one")
    payload = session.scalars(select(RawObservation)).one().payload
    assert set(payload) == set(observations.PAYLOAD_KEYS)
    assert "body" not in payload
    assert "html" not in payload
    assert "subject" not in payload  # only a hash, never the text


def test_message_body_text_never_reaches_the_observation(session, sample_paths):
    mail = parse_eml(sample_paths[0].read_bytes())
    payload = observations.to_payload(mail)
    dumped = json.dumps(payload)
    # The sample fixture carries prose in the body; none of it may be stored.
    body_words = [w for w in ("unsubscribe", "newsletter", "hello") if w in dumped.lower()]
    assert body_words == []


def test_an_unexpected_field_is_refused(session):
    with pytest.raises(ValueError, match="unexpected observation fields"):
        observations.store(
            session,
            source_kind=observations.EMAIL_METADATA,
            source_ref="eml:bad",
            payload={"schema": 1, "from_domain": "x.test", "body": "a whole email"},
        )


def test_round_trip_reconstructs_the_parse(session, sample_paths):
    mail = parse_eml(sample_paths[0].read_bytes())
    payload = observations.to_payload(mail)
    restored = observations.from_payload(json.loads(json.dumps(payload, default=str)))
    assert restored.from_domain == mail.from_domain
    assert restored.pixel_hosts == mail.pixel_hosts
    assert restored.redirector_hosts == mail.redirector_hosts
    assert len(restored.pixels) == len(mail.pixels)


# --- what a rebuild does ----------------------------------------------
def _build_corpus(session, sample_paths):
    for i, path in enumerate(sample_paths):
        _ingest(session, path, f"eml:{i}")
    RelationshipEngine(session).correlate()
    session.commit()


def test_rebuild_reproduces_the_claim_set(session, sample_paths):
    _build_corpus(session, sample_paths)
    result = rebuild.rebuild(session)
    assert result["reproduced"] is True, result
    assert result["after"]["edges"] == result["before"]["edges"]
    assert result["observations_replayed"] == len(sample_paths)


def test_rebuild_is_repeatable(session, sample_paths):
    _build_corpus(session, sample_paths)
    first = rebuild.rebuild(session)
    second = rebuild.rebuild(session)
    assert first["graph_digest"]["after"] == second["graph_digest"]["after"]


def test_claims_can_be_destroyed_and_recovered(session, sample_paths):
    _build_corpus(session, sample_paths)
    before = rebuild.graph_digest(session)

    for edge in session.scalars(select(Edge)).all():
        session.delete(edge)
    session.commit()
    assert rebuild.graph_digest(session) != before

    rebuild.rebuild(session)
    assert rebuild.graph_digest(session) == before


def test_rebuild_survives_a_rule_change_without_losing_the_observation(session, sample_paths, monkeypatch):
    _build_corpus(session, sample_paths)
    observations_before = len(session.scalars(select(RawObservation)).all())

    original = classify.RULES["R-OBS-1"]
    monkeypatch.setitem(
        classify.RULES,
        "R-OBS-1",
        classify.Rule(
            original.id, original.classification, original.relation, original.description,
            "A revised caveat.",
        ),
    )
    result = rebuild.rebuild(session)

    # The claim set is the same shape but the claims are not the same claims,
    # and that difference is visible rather than silent.
    assert result["reproduced"] is False
    assert len(session.scalars(select(RawObservation)).all()) == observations_before
    new_caveats = {e.caveat for e in session.scalars(select(Edge).where(Edge.rule_id == "R-OBS-1"))}
    assert new_caveats == {"A revised caveat."}


def test_observations_are_untouched_by_a_rebuild(session, sample_paths):
    _build_corpus(session, sample_paths)
    hashes_before = sorted(r.payload_hash for r in session.scalars(select(RawObservation)))
    rebuild.rebuild(session)
    hashes_after = sorted(r.payload_hash for r in session.scalars(select(RawObservation)))
    assert hashes_before == hashes_after


# --- layer 3 keeps its own raw record --------------------------------
def test_rebuild_does_not_touch_sealed_events_or_the_vault(session, sample_paths):
    _build_corpus(session, sample_paths)
    shadow_events.record(
        session,
        kind=shadow_events.DECOY_ACCESS,
        subject_ref="decoy:one",
        subject_kind="decoy",
        origin_hmac="a" * 64,
        detail="decoy fetched",
    )
    events_before = len(session.scalars(select(ShadowEvent)).all())

    rebuild.rebuild(session)

    assert len(session.scalars(select(ShadowEvent)).all()) == events_before
    assert vault.verify(session)["ok"] is True


def test_a_confirmed_bridge_is_restored_not_forgotten(session, sample_paths):
    _build_corpus(session, sample_paths)
    shadow_events.record(
        session,
        kind=shadow_events.DECOY_ACCESS,
        subject_ref="decoy:one",
        subject_kind="decoy",
        origin_hmac="a" * 64,
        detail="decoy fetched",
    )
    shadow_graph.project(session)

    org = session.scalars(select(Node).where(Node.kind == "organization")).first()
    proposal = bridges.propose(
        session,
        surveillance_key=org.key,
        adversarial_key="origin:" + ("a" * 64)[:12],
        rationale="same network range appears in headers and decoy traffic",
    )
    bridges.confirm(session, proposal.id, by="owner", note="checked the chain")

    result = rebuild.rebuild(session)

    assert result["bridges_restored"]["restored"] == 1
    edge = session.scalars(select(Edge).where(Edge.rule_id == "R-SHD-4")).one()
    assert edge.classification == "hypothesized"
    assert edge.confidence <= 0.65
    assert edge.evidence, "a restored bridge still carries its provenance"
    assert session.get(BridgeProposal, proposal.id).status == "confirmed"


def test_rejected_bridges_stay_rejected_after_a_rebuild(session, sample_paths):
    _build_corpus(session, sample_paths)
    shadow_events.record(
        session,
        kind=shadow_events.DECOY_ACCESS,
        subject_ref="decoy:one",
        subject_kind="decoy",
        origin_hmac="a" * 64,
        detail="decoy fetched",
    )
    shadow_graph.project(session)
    org = session.scalars(select(Node).where(Node.kind == "organization")).first()
    proposal = bridges.propose(
        session,
        surveillance_key=org.key,
        adversarial_key="origin:" + ("a" * 64)[:12],
        rationale="shared CDN, which is very weak evidence indeed",
    )
    bridges.reject(session, proposal.id, by="owner", note="CDN is shared by thousands")

    rebuild.rebuild(session)

    assert session.scalars(select(Edge).where(Edge.rule_id == "R-SHD-4")).all() == []
    assert session.get(BridgeProposal, proposal.id).status == "rejected"


def test_rebuild_gives_no_one_a_way_to_launder_a_bridge(session, sample_paths):
    """A rebuild must never create a cross-layer edge that was not confirmed."""
    _build_corpus(session, sample_paths)
    shadow_events.record(
        session,
        kind=shadow_events.DECOY_ACCESS,
        subject_ref="decoy:one",
        subject_kind="decoy",
        origin_hmac="a" * 64,
        detail="decoy fetched",
    )
    shadow_graph.project(session)
    rebuild.rebuild(session)
    assert session.scalars(select(Edge).where(Edge.rule_id == "R-SHD-4")).all() == []
    assert session.scalars(select(BridgeProposal)).all() == []


# --- the replay must cover every derivation source --------------------
def test_counter_observation_edges_survive_a_rebuild(session, sample_paths):
    """Regression: the replay once forgot the counter-observation projection.

    Canary hits are raw observations. The R-MIR-* edges are derived from them, so a
    rebuild that replays only the mail path silently erases the entire
    counter-observation graph. Twenty-one edges vanished this way before the
    rebuild's own digest caught it.
    """
    from phantom.mirror import tokens
    from phantom.mirror.beacon import record_observation
    from phantom.mirror.countergraph import build as build_countergraph

    _build_corpus(session, sample_paths)
    canary = tokens.mint(session, "canary-under-test", note="regression")
    for ua, origin in [
        ("python-requests/2.32.3", "203.0.113.10"),
        ("python-requests/2.32.3", "203.0.113.11"),
        ("Scrapy/2.11 (+https://scrapy.org)", "198.51.100.7"),
    ]:
        record_observation(
            session, token=canary.token, headers={"user-agent": ua}, source_ip=origin
        )
    build_countergraph(session)
    session.commit()

    before = len(session.scalars(select(Edge).where(Edge.rule_id.like("R-MIR-%"))).all())
    assert before > 0, "the fixture did not produce counter-observation edges"

    result = rebuild.rebuild(session)

    after = len(session.scalars(select(Edge).where(Edge.rule_id.like("R-MIR-%"))).all())
    assert after == before
    assert result["reproduced"] is True

"""Layer 3: what it records, and the two invariants that keep it honest.

The tests that matter most are the identity-separation ones. They exist because
"these layers are separate" is the kind of claim that quietly stops being true
after a refactor.
"""
from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select, text

from phantom import egress
from phantom.engine import classify
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.models import Edge
from phantom.shadow import bridges, indicators, mirrorlock, quarantine, temporal, vault
from phantom.shadow import events as shadow_events
from phantom.shadow import graph as shadow_graph
from phantom.shadow import report as shadow_report
from phantom.shadow.models import BridgeProposal, QuarantinedPayload, ShadowEvent, VaultRecord

SCRIPTED = dict(client_family="scripted", client_tool="python-requests")


def _event(session, **kwargs):
    base = dict(
        kind=shadow_events.DECOY_ACCESS,
        subject_ref="decoy:deck v1",
        subject_kind="decoy",
        origin_hmac="a" * 64,
        client_hash="b" * 64,
        asn=64500,
        asn_org="Example Cloud",
        detail="decoy fetched",
    )
    base.update(kwargs)
    return shadow_events.record(session, **base)


def _dark_origin(n: int) -> str:
    return (chr(ord("a") + n)) * 64


# --- events ------------------------------------------------------------
def test_event_is_content_fingerprinted_and_sealed(session):
    event = _event(session)
    assert len(event.event_hash) == 64
    assert event.vault_seq is not None
    assert event.alt_explanations, "every event carries an innocent reading"


def test_identical_observation_is_not_recorded_twice(session):
    at = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
    first = _event(session, occurred_at=at)
    second = _event(session, occurred_at=at)
    assert first.event_hash == second.event_hash
    assert len(session.scalars(select(VaultRecord)).all()) == 1


def test_event_without_alternative_explanation_is_refused(session):
    with pytest.raises(ValueError, match="over-read"):
        _event(session, alt_explanations=[])


def test_unknown_event_kind_is_refused(session):
    with pytest.raises(ValueError, match="unknown shadow event kind"):
        _event(session, kind="made_up_thing")


def test_credentials_in_a_request_are_stripped_before_storage(session):
    _event(
        session,
        detail="caller sent password=hunter2 and Bearer abcdefghijklmnop123456",
    )
    dump = str(session.execute(text("select * from shadow_events")).all())
    assert "hunter2" not in dump
    assert "abcdefghijklmnop123456" not in dump
    assert "credential material refused" in dump
    assert session.scalars(select(ShadowEvent)).first().credential_material_refused is True


# --- vault -------------------------------------------------------------
def test_chain_verifies_when_untouched(session):
    for i in range(3):
        _event(session, occurred_at=dt.datetime(2026, 1, 1, 12, i, tzinfo=dt.UTC))
    result = vault.verify(session)
    assert result["ok"] is True
    assert result["checked"] == 3


def test_editing_a_stored_record_breaks_its_seal(session):
    for i in range(3):
        _event(session, occurred_at=dt.datetime(2026, 1, 1, 12, i, tzinfo=dt.UTC))
    victim = session.scalars(
        select(VaultRecord).order_by(VaultRecord.seq).offset(1).limit(1)
    ).first()
    victim.subject_ref = "decoy:something else"
    session.commit()

    result = vault.verify(session)
    assert result["ok"] is False
    assert "seal mismatch" in result["reason"]


def test_deleting_a_record_breaks_the_chain(session):
    for i in range(3):
        _event(session, occurred_at=dt.datetime(2026, 1, 1, 12, i, tzinfo=dt.UTC))
    middle = session.scalars(
        select(VaultRecord).order_by(VaultRecord.seq).offset(1).limit(1)
    ).first()
    session.delete(middle)
    session.commit()

    result = vault.verify(session)
    assert result["ok"] is False
    assert "chain link broken" in result["reason"]


def test_empty_vault_verifies_trivially(session):
    assert vault.verify(session) == {
        "ok": True, "checked": 0, "head": vault.GENESIS, "reason": "nothing recorded yet",
    }


# --- MirrorLock --------------------------------------------------------
def test_decryption_is_denied_by_default(session):
    blob = mirrorlock.lock(session, "board pack", b"secret numbers")
    result = mirrorlock.request(session, blob.id, requester_label="someone")
    assert result["granted"] is False
    assert result["plaintext"] is None
    event = session.scalars(
        select(ShadowEvent).where(ShadowEvent.kind == shadow_events.PROTECTED_DATA_REQUEST)
    ).one()
    assert event.outcome == shadow_events.DENIED


def test_a_live_grant_permits_exactly_that_read(session):
    blob = mirrorlock.lock(session, "board pack", b"secret numbers")
    mirrorlock.grant(session, blob.id, minutes=5)
    result = mirrorlock.request(session, blob.id, requester_label="owner")
    assert result["granted"] is True
    assert result["plaintext"] == "secret numbers"


def test_revoking_a_grant_restores_denial(session):
    blob = mirrorlock.lock(session, "board pack", b"secret numbers")
    mirrorlock.grant(session, blob.id, minutes=5)
    assert mirrorlock.request(session, blob.id)["granted"] is True
    mirrorlock.revoke(session, blob.id)
    assert mirrorlock.request(session, blob.id)["granted"] is False


def test_absurd_grant_windows_are_refused(session):
    blob = mirrorlock.lock(session, "x", b"y")
    with pytest.raises(ValueError):
        mirrorlock.grant(session, blob.id, minutes=0)
    with pytest.raises(ValueError):
        mirrorlock.grant(session, blob.id, minutes=60 * 24 + 1)


def test_refused_request_never_leaks_the_content(session):
    blob = mirrorlock.lock(session, "board pack", b"secret numbers")
    result = mirrorlock.request(
        session, blob.id, justification="send password=hunter2 please"
    )
    assert result["plaintext"] is None
    dump = str(session.execute(text("select * from shadow_events")).all())
    assert "secret numbers" not in dump
    assert "hunter2" not in dump


def test_blob_integrity_survives_a_key_rotation_mismatch(session):
    blob = mirrorlock.lock(session, "x", b"y")
    assert mirrorlock.verify_integrity(session, blob.id)["ok"] is True


# --- quarantine --------------------------------------------------------
def test_executable_payload_is_flagged_not_run(session):
    result = quarantine.capture(
        session, b"MZ\x90\x00" + b"\x00" * 64, source_ref="mail:1", declared_type="application/pdf"
    )
    assert result["executable_signature"] is True
    assert result["executed"] is False
    assert result["sniffed_type"] == "windows-executable"
    assert "declared" in result["note"].lower() or "evidence only" in result["note"].lower()


def test_same_payload_twice_is_stored_once(session):
    payload = b"%PDF-1.7 not really a pdf"
    quarantine.capture(session, payload, source_ref="mail:1")
    quarantine.capture(session, payload, source_ref="mail:2")
    assert len(session.scalars(select(QuarantinedPayload)).all()) == 1


def test_quarantine_records_an_event_with_alternative_readings(session):
    quarantine.capture(session, b"MZ\x90\x00abc", source_ref="mail:9")
    event = session.scalars(
        select(ShadowEvent).where(ShadowEvent.kind == shadow_events.PAYLOAD_QUARANTINED)
    ).one()
    assert event.outcome == shadow_events.QUARANTINED
    assert any("legitimate" in line.lower() for line in event.alt_explanations)


# --- recurrence and proximity -----------------------------------------
def test_recurring_indicator_is_counted_with_its_caveat(session):
    _event(session, subject_ref="decoy:one", origin_hmac=_dark_origin(0))
    _event(session, subject_ref="decoy:two", origin_hmac=_dark_origin(0))
    rows = indicators.recurring(session)
    origin_rows = [r for r in rows if r["indicator_type"] == "origin"]
    assert origin_rows
    assert origin_rows[0]["events"] == 2
    assert origin_rows[0]["distinct_subjects"] == 2
    assert "not of a person" in origin_rows[0]["caveat"]
    assert origin_rows[0]["alternative_explanations"]


def test_single_events_are_not_called_recurring(session):
    _event(session, origin_hmac=_dark_origin(3))
    assert indicators.recurring(session) == []


def test_co_occurrence_is_capped_and_hedged(session):
    base = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
    _event(session, subject_ref="decoy:one", origin_hmac=_dark_origin(0), occurred_at=base)
    _event(
        session, subject_ref="decoy:two", origin_hmac=_dark_origin(0),
        occurred_at=base + dt.timedelta(minutes=4),
    )
    candidates = temporal.co_occurrences(session, window_minutes=60)
    assert candidates
    for candidate in candidates:
        assert candidate["classification"] == "hypothesized"
        assert candidate["confidence"] <= 0.65
        assert len(candidate["alternative_explanations"]) >= 3
        assert "not a link" in candidate["caveat"]


def test_events_outside_the_window_do_not_co_occur(session):
    base = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
    _event(session, subject_ref="decoy:one", origin_hmac=_dark_origin(0), occurred_at=base)
    _event(
        session, subject_ref="decoy:two", origin_hmac=_dark_origin(0),
        occurred_at=base + dt.timedelta(hours=6),
    )
    assert temporal.co_occurrences(session, window_minutes=60) == []


# --- identity separation (the invariants) -----------------------------
def test_engine_refuses_a_cross_layer_edge_from_ingestion(session):
    engine = RelationshipEngine(session)
    engine._node("org:domain:acme.test", "organization", "Acme")
    engine._node("origin:" + "a" * 12, "origin", "origin…aaaaaa")
    session.commit()

    with pytest.raises(classify.UnconfirmedCrossLayerEdge):
        engine._edge(
            "R-SHD-4",
            "org:domain:acme.test",
            "origin:" + "a" * 12,
            evidence_kind="guess",
            detail="they look related",
            source_ref="test:1",
        )


def test_projection_creates_no_cross_layer_edge(session):
    _event(session)
    shadow_graph.project(session)
    rules = {e.rule_id for e in session.scalars(select(Edge))}
    assert "R-SHD-4" not in rules
    assert session.scalars(select(BridgeProposal)).all() == []


def test_adversarial_projection_stays_out_of_the_surveillance_namespace(session):
    _event(session)
    shadow_graph.project(session)
    view = shadow_graph.to_cytoscape(session)
    kinds = {el["data"]["kind"] for el in view["elements"] if "relation" not in el["data"]}
    assert kinds <= {"origin", "client", "asn", "decoy", "protected_object", "payload"}
    assert view["separation"]["automatic_merges"] == 0


# --- bridges -----------------------------------------------------------
def _prepare_pair(session) -> tuple[str, str]:
    _event(session, origin_hmac=_dark_origin(0))
    shadow_graph.project(session)
    engine = RelationshipEngine(session)
    engine._node("org:domain:acme.test", "organization", "Acme")
    session.commit()
    return "org:domain:acme.test", "origin:" + _dark_origin(0)[:12]


def test_bridge_requires_a_rationale_naming_the_observable(session):
    surveillance, adversarial = _prepare_pair(session)
    with pytest.raises(ValueError, match="shared observable"):
        bridges.propose(
            session,
            surveillance_key=surveillance,
            adversarial_key=adversarial,
            rationale="looks suss",
        )


def test_bridge_refuses_two_entities_from_the_same_layer(session):
    _event(session)
    shadow_graph.project(session)
    engine = RelationshipEngine(session)
    engine._node("origin:" + "f" * 12, "origin", "origin…ffffff")
    session.commit()
    with pytest.raises(ValueError, match="surveillance-layer"):
        bridges.propose(
            session,
            surveillance_key="origin:" + "f" * 12,
            adversarial_key="origin:" + _dark_origin(0)[:12],
            rationale="both are origins, and this should not be allowed at all",
        )


def test_proposing_twice_does_not_create_two_proposals(session):
    surveillance, adversarial = _prepare_pair(session)
    first = bridges.propose(
        session, surveillance_key=surveillance, adversarial_key=adversarial,
        rationale="same ASN observed in the header chain",
    )
    second = bridges.propose(
        session, surveillance_key=surveillance, adversarial_key=adversarial,
        rationale="same ASN observed in the header chain",
    )
    assert first.id == second.id
    assert len(session.scalars(select(BridgeProposal)).all()) == 1


def test_confirming_a_bridge_creates_one_hedged_edge(session):
    surveillance, adversarial = _prepare_pair(session)
    proposal = bridges.propose(
        session, surveillance_key=surveillance, adversarial_key=adversarial,
        rationale="same ASN and client family in the observed traffic",
    )
    outcome = bridges.confirm(session, proposal.id, by="owner", note="checked the evidence")
    assert outcome["status"] == "confirmed"
    assert outcome["confidence"] <= 0.65
    assert "human confirmed" in outcome["caveat"].lower()

    edges = session.scalars(select(Edge).where(Edge.rule_id == "R-SHD-4")).all()
    assert len(edges) == 1
    assert edges[0].classification == "hypothesized"
    assert edges[0].evidence, "a bridge still needs provenance"


def test_relayed_confirm_is_idempotent(session):
    surveillance, adversarial = _prepare_pair(session)
    proposal = bridges.propose(
        session, surveillance_key=surveillance, adversarial_key=adversarial,
        rationale="same network range observed twice",
    )
    first = bridges.confirm(session, proposal.id)
    second = bridges.confirm(session, proposal.id)
    assert first["edge_id"] == second["edge_id"]
    assert second.get("already") is True


def test_rejecting_a_bridge_creates_no_edge_and_blocks_confirmation(session):
    surveillance, adversarial = _prepare_pair(session)
    proposal = bridges.propose(
        session, surveillance_key=surveillance, adversarial_key=adversarial,
        rationale="shared CDN, which is very weak evidence",
    )
    bridges.reject(session, proposal.id, by="owner", note="CDN is shared by thousands")
    with pytest.raises(ValueError, match="rejected"):
        bridges.confirm(session, proposal.id)

    assert session.scalars(select(Edge).where(Edge.rule_id == "R-SHD-4")).all() == []


def test_surveillance_nodes_only_appear_when_asked_for(session):
    surveillance, adversarial = _prepare_pair(session)
    proposal = bridges.propose(
        session, surveillance_key=surveillance, adversarial_key=adversarial,
        rationale="same ASN observed in both layers",
    )
    bridges.confirm(session, proposal.id)

    separated = shadow_graph.to_cytoscape(session)
    joined = shadow_graph.to_cytoscape(session, include_surveillance=True)

    separated_layers = {
        el["data"]["layer"] for el in separated["elements"] if "relation" not in el["data"]
    }
    joined_layers = {el["data"]["layer"] for el in joined["elements"] if "relation" not in el["data"]}

    # The layer-3 view stays adversarial, but it still reports that a bridge
    # exists rather than pretending the join is not there.
    assert separated_layers == {"adversarial"}
    assert len(separated["confirmed_bridges"]) == 1
    assert separated["confirmed_bridges"][0]["endpoints_visible"] is False
    assert separated["bridges_drawn"] == []

    assert "surveillance" in joined_layers
    assert joined["confirmed_bridges"][0]["endpoints_visible"] is True
    assert len(joined["bridges_drawn"]) == 1


# --- report and guardrails --------------------------------------------
def test_report_states_what_the_layer_cannot_tell_you(session):
    _event(session)
    shadow_graph.project(session)
    report = shadow_report.adversarial_report(session)
    joined = " ".join(report["cannot_tell_you"]).lower()
    assert "who" in joined
    assert "hostile" in joined
    assert report["layers"]["separation_rule"]


def test_guardrails_refuse_every_active_capability(session):
    guardrails = shadow_report.guardrails()
    assert guardrails["active_probing_of_third_parties"] is False
    assert guardrails["outbound_requests_to_requester"] == 0
    assert guardrails["retaliation_enabled"] is False
    assert guardrails["recovered_credentials_stored"] is False
    assert guardrails["quarantined_payloads_executed"] is False
    assert guardrails["automatic_layer_merges"] == 0


def test_a_refusal_is_not_treated_as_an_accusation(session):
    blob = mirrorlock.lock(session, "x", b"y")
    mirrorlock.request(session, blob.id, requester_label="someone")
    report = shadow_report.adversarial_report(session)
    assert report["refusal_note"]
    assert "expired grant" in report["refusal_note"]


def test_layer3_work_makes_no_outbound_request(session):
    before = len(egress.read_log())
    _event(session)
    blob = mirrorlock.lock(session, "x", b"y")
    mirrorlock.request(session, blob.id)
    quarantine.capture(session, b"MZ\x90\x00", source_ref="mail:1")
    shadow_graph.project(session)
    shadow_report.adversarial_report(session)
    assert len(egress.read_log()) == before


# --- HTTP --------------------------------------------------------------
def test_mirrorlock_round_trip_over_http(client):
    import base64

    locked = client.post(
        "/api/shadow/mirrorlock",
        json={"label": "board pack", "content_b64": base64.b64encode(b"numbers").decode()},
    ).json()
    blob_id = locked["blob_id"]

    denied = client.post(
        f"/api/shadow/mirrorlock/{blob_id}/request", json={"requester_label": "someone"}
    ).json()
    assert denied["granted"] is False
    assert denied["plaintext"] is None

    client.post(f"/api/shadow/mirrorlock/{blob_id}/grant", json={"minutes": 5})
    granted = client.post(
        f"/api/shadow/mirrorlock/{blob_id}/request", json={"requester_label": "owner"}
    ).json()
    assert granted["granted"] is True
    assert granted["plaintext"] == "numbers"


def test_report_endpoint_reports_zero_automatic_merges(client):
    report = client.get("/api/shadow/report").json()
    assert report["guardrails"]["automatic_layer_merges"] == 0
    assert report["layer"] == "adversarial"
    assert report["vault"]["ok"] is True


def test_bridge_endpoint_rejects_a_nonsense_pair(client):
    response = client.post(
        "/api/shadow/bridges",
        json={
            "surveillance_key": "org:domain:nowhere.test",
            "adversarial_key": "origin:whatever",
            "rationale": "not a real pair at all",
        },
    )
    assert response.status_code == 400


def test_vault_endpoint_reports_intact_chain(client):
    client.post("/api/shadow/quarantine", json={"payload_b64": "TVqQAAM=", "source_ref": "x"})
    assert client.get("/api/shadow/vault").json()["ok"] is True

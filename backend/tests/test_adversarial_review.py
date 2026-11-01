"""Regression tests for the adversarial review of 2026-11-01.

One test per finding, written to fail if the specific claim becomes true again.
The point is not coverage, it is that each of these was a real path and the test
names the path rather than the function.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json

import pytest
from sqlalchemy import select, update

from phantom import egress
from phantom.collector.headers import ParsedEmail
from phantom.collector.pixels import LinkObservation, PixelObservation
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.redaction import redact_ips, safe_url

# ---------------------------------------------------------------------------
# Finding 1: the allowlist checked the name and never the scheme
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://oauth2.googleapis.com/revoke",     # cleartext OAuth
        "https://oauth2.googleapis.com:8443/x",    # unexpected port
        "https://user:pass@oauth2.googleapis.com/token",  # user-info smuggling
        "https://142.250.185.74/token",            # IP literal, no name to allowlist
        "https://not-on-the-list.example/x",       # not allowlisted at all
    ],
)
def test_egress_refuses_these_destinations(url):
    with pytest.raises(egress.EgressBlocked):
        egress.check(url)


def test_egress_refuses_a_name_that_resolves_somewhere_private(monkeypatch):
    """Rebinding: an allowlisted name pointed at the operator's own machine."""
    def fake_getaddrinfo(host, port, **kwargs):
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(egress.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(egress.EgressBlocked, match="not a public address"):
        egress.check("https://oauth2.googleapis.com/token")


# ---------------------------------------------------------------------------
# Finding 3: an OAuth token reached a log through a query string
# ---------------------------------------------------------------------------


def test_logged_urls_never_carry_query_values():
    safe = safe_url("https://oauth2.googleapis.com/revoke?token=SECRETTOKEN123")
    assert "SECRETTOKEN123" not in safe
    assert "token=<withheld>" in safe


def test_revocation_puts_the_token_in_the_body(monkeypatch):
    from phantom.collector import gmail

    captured = {}

    def fake_request(method, url, **kwargs):
        captured.update({"method": method, "url": url, **kwargs})
        return None

    monkeypatch.setattr(egress, "request", fake_request)
    gmail.revoke("SECRETTOKEN123")

    assert "SECRETTOKEN123" not in captured["url"]
    assert captured["data"] == {"token": "SECRETTOKEN123"}


def test_legacy_log_lines_are_scrubbed(tmp_path, monkeypatch):
    log = tmp_path / "egress.jsonl"
    log.write_text(
        json.dumps(
            {
                "at": "2026-10-01T00:00:00+00:00",
                "url": "https://oauth2.googleapis.com/revoke?token=LEAKED",
                "purpose": "revoke",
                "allowed": True,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        egress, "settings", dataclasses.replace(egress.settings, egress_log=log)
    )
    assert egress.scrub_legacy_log() == 1
    assert "LEAKED" not in log.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Finding 2: a caller could authorise its own read
# ---------------------------------------------------------------------------


def test_a_grant_needs_the_operator_code(session):
    from phantom.shadow import mirrorlock

    blob = mirrorlock.lock(session, "pack", b"numbers")
    with pytest.raises(mirrorlock.NotAuthorised):
        mirrorlock.grant(session, blob.id, minutes=5, approval="")
    with pytest.raises(mirrorlock.NotAuthorised):
        mirrorlock.grant(session, blob.id, minutes=5, approval="guessed")

    assert mirrorlock.request(session, blob.id)["granted"] is False


def test_the_approval_code_is_bound_to_object_and_duration(session):
    from phantom.shadow import mirrorlock

    a = mirrorlock.lock(session, "a", b"aaa")
    b = mirrorlock.lock(session, "b", b"bbb")
    code_for_a = mirrorlock.approval_code(a.id, 5)

    with pytest.raises(mirrorlock.NotAuthorised):
        mirrorlock.grant(session, b.id, minutes=5, approval=code_for_a)
    with pytest.raises(mirrorlock.NotAuthorised):
        mirrorlock.grant(session, a.id, minutes=60, approval=code_for_a)

    granted = mirrorlock.grant(session, a.id, minutes=5, approval=code_for_a)
    assert granted.authorization == "local-approval-code"
    assert granted.granted_by


def test_the_requester_label_is_recorded_as_a_claim(session):
    from phantom.shadow import mirrorlock
    from phantom.shadow.models import ShadowEvent

    blob = mirrorlock.lock(session, "pack", b"numbers")
    mirrorlock.request(session, blob.id, requester_label="the owner")
    event = session.scalars(
        select(ShadowEvent).where(ShadowEvent.kind == "protected_data_request")
    ).first()
    assert "claimed, unverified" in event.detail


# ---------------------------------------------------------------------------
# Finding 4: the vault verified its chain and not the evidence
# ---------------------------------------------------------------------------


def _record_event(session):
    from phantom.shadow import events

    return events.record(
        session,
        kind=events.DECOY_ACCESS,
        subject_ref="vault:doc-1",
        detail="someone fetched the decoy",
    )


def test_vault_passes_on_an_untouched_record(session):
    from phantom.shadow import vault

    _record_event(session)
    result = vault.verify(session)
    assert result["ok"] is True
    assert result["event_contents_checked"] is True


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("detail", "someone did nothing at all"),
        ("client_family", "forged-client"),
        ("asn_org", "forged-network"),
        ("subject_kind", "something-else"),
        ("credential_material_refused", True),
    ],
)
def test_vault_detects_rewritten_event_contents(session, column, value):
    """The gap the review named: a seal that survives the evidence changing."""
    from phantom.shadow import vault
    from phantom.shadow.models import ShadowEvent

    event = _record_event(session)
    session.execute(
        update(ShadowEvent).where(ShadowEvent.id == event.id).values({column: value})
    )
    session.commit()

    result = vault.verify(session)
    assert result["ok"] is False
    assert "event contents changed" in result["reason"]


def test_vault_detects_rewritten_alternative_explanations(session):
    from phantom.shadow import vault
    from phantom.shadow.models import ShadowEvent

    event = _record_event(session)
    session.execute(
        update(ShadowEvent)
        .where(ShadowEvent.id == event.id)
        .values({"alt_explanations": ["a single convenient story"]})
    )
    session.commit()
    assert vault.verify(session)["ok"] is False


def test_rows_from_an_older_canonical_form_are_not_silently_passed(session):
    from phantom.shadow import vault
    from phantom.shadow.models import ShadowEvent

    event = _record_event(session)
    session.execute(
        update(ShadowEvent)
        .where(ShadowEvent.id == event.id)
        .values({"fingerprint_version": 1})
    )
    session.commit()
    result = vault.verify(session)
    assert result["ok"] is False
    assert "unverifiable event" in result["reason"]


# ---------------------------------------------------------------------------
# Finding 6: one message must contribute one provider observation
# ---------------------------------------------------------------------------


def _mail(message_id="m1", **kwargs):
    base = dict(
        message_id=message_id,
        sent_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC),
        from_address="ops@acme-corp.example",
        from_domain="acme-corp.example",
        display_name="Acme Inc",
    )
    base.update(kwargs)
    return ParsedEmail(**base)


def test_a_pixel_and_a_redirect_to_one_provider_count_once(session):
    from phantom.models import Edge

    mail = _mail(
        pixels=[
            PixelObservation(
                url="https://px.mailchimp.com/o.gif?mc_eid=abc",
                host="px.mailchimp.com",
                reasons=["1x1", "hidden"],
            )
        ],
        links=[
            LinkObservation(
                url="https://click.mailchimp.com/c/abc",
                host="click.mailchimp.com",
                is_redirector=True,
                target_host="acme-corp.example",
            )
        ],
    )
    RelationshipEngine(session).ingest(mail, source_ref="eml:m1")
    provider_edges = [
        edge for edge in session.scalars(select(Edge)) if edge.rule_id == "R-OBS-2"
    ]
    assert len(provider_edges) == 1
    assert provider_edges[0].observation_count == 1


# ---------------------------------------------------------------------------
# Finding 5: a forged display name could create a relationship
# ---------------------------------------------------------------------------


def _identity_pair(session, *, shared_relay: bool):
    engine = RelationshipEngine(session)
    hops = [{"from_host": "relay.shared.example", "by_host": "mx.recipient.example"}] if shared_relay else []
    engine.ingest(
        _mail("m-acme", received_hops=hops), source_ref="eml:m-acme"
    )
    engine.ingest(
        _mail(
            "m-lookalike",
            from_address="ops@acme-mailer.example",
            from_domain="acme-mailer.example",
            display_name="Acme Inc",
            received_hops=hops,
        ),
        source_ref="eml:m-lookalike",
    )
    return engine


def test_the_same_display_name_alone_creates_no_edge(session):
    from phantom.models import Edge

    engine = _identity_pair(session, shared_relay=False)
    engine.correlate()

    assert not [e for e in session.scalars(select(Edge)) if e.rule_id == "R-HYP-1"]
    unresolved = engine.unresolved()
    assert unresolved["identity_claims_without_corroboration"]


def test_the_same_display_name_with_shared_infrastructure_is_a_hypothesis(session):
    from phantom.models import Edge

    engine = _identity_pair(session, shared_relay=True)
    engine.correlate()

    edges = [e for e in session.scalars(select(Edge)) if e.rule_id == "R-HYP-1"]
    assert len(edges) == 1
    assert edges[0].classification == "hypothesized"


# ---------------------------------------------------------------------------
# Finding 7: a permission flag with nobody behind it
# ---------------------------------------------------------------------------


def test_consent_without_an_attribution_is_refused(session):
    from phantom.auth.consent import ConsentError, ConsentService

    with pytest.raises(ConsentError, match="attest"):
        ConsentService(session).enroll(gmail_address="a@b.com", consent_gmail=True)


def test_an_expired_grant_stops_holding_the_values(session):
    from phantom.auth.consent import ConsentService

    service = ConsentService(session)
    record = service.enroll(
        gmail_address="a@b.com",
        consent_gmail=True,
        attested_by="aadi",
        attestation="this mailbox is mine",
    )
    assert record.gmail_address

    record.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
    session.commit()

    assert service.clear_expired() == 1
    session.refresh(record)
    assert record.gmail_address is None
    assert service.active() == []


# ---------------------------------------------------------------------------
# Finding 9: a public endpoint that grows a table for anyone who asks
# ---------------------------------------------------------------------------


def test_a_canary_stops_recording_past_its_budget(session, monkeypatch):
    from phantom.mirror import beacon, tokens

    canary = tokens.mint(session, "pitch deck")
    token = getattr(canary, "token", None) or (
        canary.url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".gif")
    )

    monkeypatch.setattr(
        beacon,
        "settings",
        dataclasses.replace(beacon.settings, canary_max_observations_per_token=1),
    )

    beacon.record_observation(
        session, token=token, source_ip="198.51.100.7", headers={"user-agent": "a"}
    )
    with pytest.raises(beacon.CapReached):
        beacon.record_observation(
            session, token=token, source_ip="198.51.100.7", headers={"user-agent": "a"}
        )


def test_the_canary_token_is_not_stored_in_the_recorded_path(session):
    from phantom.mirror import beacon, tokens

    canary = tokens.mint(session, "deck")
    token = getattr(canary, "token", None) or (
        canary.url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".gif")
    )
    observation, _ = beacon.record_observation(
        session,
        token=token,
        source_ip="198.51.100.7",
        headers={"user-agent": "a"},
        path=f"/mirror/b/{token}.gif",
    )
    assert token not in (observation.path or "")


# ---------------------------------------------------------------------------
# Finding 10: metadata is still data
# ---------------------------------------------------------------------------


def test_stored_observations_do_not_keep_recipient_identifiers():
    from phantom import observations

    mail = _mail(
        pixels=[
            PixelObservation(
                url="https://px.mailchimp.com/o.gif?mc_eid=RECIPIENT-SECRET&mkt_tok=TOK",
                host="px.mailchimp.com",
                params={"mc_eid": "RECIPIENT-SECRET", "mkt_tok": "TOK"},
            )
        ],
        links=[
            LinkObservation(
                url="https://click.mailchimp.com/c?uid=RECIPIENT-SECRET",
                host="click.mailchimp.com",
                params={"uid": "RECIPIENT-SECRET"},
            )
        ],
    )
    payload = json.dumps(observations.to_payload(mail))
    assert "RECIPIENT-SECRET" not in payload
    assert "TOK" not in payload.replace("mkt_tok", "")


def test_stored_observations_withhold_ip_addresses():
    from phantom import observations

    mail = _mail(
        received_hops=[
            {"from_host": "mail.acme-corp.example", "from_ip": "203.0.113.9"}
        ]
    )
    payload = json.dumps(observations.to_payload(mail))
    assert "203.0.113.9" not in payload
    assert "mail.acme-corp.example" in payload


def test_ip_redaction_leaves_timestamps_alone():
    hop = {"by_host": "mx.example", "at": "Thu, 1 Oct 2026 12:34:56 +0000"}
    assert redact_ips(hop)["at"] == hop["at"]

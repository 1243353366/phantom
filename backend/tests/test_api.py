"""The HTTP surface must not offer a way to export anyone's data."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from phantom.main import app


@pytest.fixture()
def client(session):
    with TestClient(app) as c:
        yield c


def test_health_declares_what_it_will_not_do(client):
    body = client.get("/api/health").json()
    assert body["sends_email"] is False
    assert body["uploads_contacts"] is False


def test_ingest_then_read_graph(client, sample_paths):
    raw = sample_paths[0].read_text(encoding="utf-8", errors="ignore")
    response = client.post(
        "/api/ingest/eml", json={"raw_email": raw, "source_ref": "api:test"}
    )
    assert response.status_code == 200
    assert response.json()["ingested"]["pixels"] == 1

    graph = client.get("/api/graph").json()
    assert graph["stats"]["edges"] > 0
    edge = next(e for e in graph["elements"] if "relation" in e["data"])
    detail = client.get(f"/api/graph/edge/{edge['data']['id']}").json()
    assert detail["evidence"], "an edge served over HTTP must carry its proof"


def test_consent_gate_is_enforced_over_http(client):
    response = client.post("/api/consent/enroll", json={"phone_number": "+15551234567"})
    assert response.status_code == 400
    assert "permission" in response.json()["detail"]


def test_enroll_and_revoke_over_http(client):
    created = client.post(
        "/api/consent/enroll",
        json={"gmail_address": "a@b.com", "consent_gmail": True},
    ).json()
    assert created["channels_authorised"] == ["email"]
    assert created["not_stored"] == ["phone_number", "work_email"]

    revoked = client.post(f"/api/consent/{created['id']}/revoke").json()
    assert revoked["fields_cleared"] is True


def test_gmail_start_offers_metadata_tier_by_default(client):
    body = client.get(
        "/api/auth/gmail/start",
        params={"client_id": "x", "redirect_uri": "http://localhost", "state": "s"},
    ).json()
    assert "gmail.metadata" in body["authorization_url"]
    assert "gmail.readonly" not in body["authorization_url"]
    assert "send mail" in body["cannot"]


def test_selfaudit_endpoint_reports_clean(client):
    body = client.get("/api/selfaudit").json()
    assert body["unmediated_egress_found"] == 0


def test_canary_round_trip_over_http(client):
    """Mint, fetch the beacon, and read the report: the whole loop."""
    created = client.post(
        "/api/mirror/canary", json={"label": "deck v1 / acme"}
    ).json()
    assert "/mirror/b/" in created["url"]
    assert "acme" not in created["url"], "the label must not travel in the URL"

    token = created["url"].rsplit("/", 1)[-1].removesuffix(".gif")
    response = client.get(
        f"/mirror/b/{token}.gif",
        headers={"user-agent": "python-requests/2.32.3", "accept": "*/*"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/gif"
    assert response.content.startswith(b"GIF89a")
    assert "no-store" in response.headers["cache-control"]

    report = client.get("/api/mirror/report").json()
    assert report["hits"] == 1
    assert report["leaked_copies"][0]["label"] == "deck v1 / acme"
    assert report["automated_hits"] == 1


def test_unknown_token_still_looks_like_an_image(client):
    """A 404 would tell a prober it had been detected."""
    response = client.get("/mirror/b/AAAAAAAAAAAAAAAAAAAAAA.gif")
    assert response.status_code == 200
    assert response.content.startswith(b"GIF89a")


def test_beacon_never_makes_an_outbound_request(client):
    from phantom import egress

    created = client.post("/api/mirror/canary", json={"label": "quiet doc"}).json()
    token = created["url"].rsplit("/", 1)[-1].removesuffix(".gif")
    before = len(egress.read_log())

    client.get(f"/mirror/b/{token}.gif", headers={"user-agent": "curl/8.5.0"})

    # Serving a canary must not itself become a beacon.
    assert len(egress.read_log()) == before


def test_raw_address_is_not_exposed_by_the_report(client):
    created = client.post("/api/mirror/canary", json={"label": "ip check"}).json()
    token = created["url"].rsplit("/", 1)[-1].removesuffix(".gif")
    client.get(f"/mirror/b/{token}.gif", headers={"user-agent": "curl/8.5.0"})

    report = client.get("/api/mirror/report").json()
    payload = str(report)
    assert "127.0.0.1" not in payload
    assert "testclient" not in payload.lower()


def test_counter_graph_endpoint_returns_no_people(client):
    created = client.post("/api/mirror/canary", json={"label": "graph doc"}).json()
    token = created["url"].rsplit("/", 1)[-1].removesuffix(".gif")
    client.get(f"/mirror/b/{token}.gif", headers={"user-agent": "Scrapy/2.11"})

    graph = client.get("/api/mirror/graph").json()
    kinds = {el["data"]["kind"] for el in graph["elements"] if "relation" not in el["data"]}
    assert kinds <= {"canary", "origin", "client", "asn"}
    assert graph["caveats"]

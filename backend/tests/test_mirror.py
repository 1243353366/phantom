"""Counter-observation: the useful part, and the limits that make it defensible."""
from __future__ import annotations

from pathlib import Path

import pytest

from phantom.mirror import RETALIATION_ENABLED, tokens
from phantom.mirror.beacon import (
    TARPIT_HARD_CAP_MS,
    TRANSPARENT_GIF,
    UnknownCanary,
    record_observation,
    tarpit_delay_ms,
)
from phantom.mirror.countergraph import build, to_cytoscape
from phantom.mirror.fingerprint import fingerprint
from phantom.mirror.report import asymmetry_report

BROWSER = {
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "accept": "image/avif,image/webp,*/*",
    "accept-language": "en-US,en;q=0.9",
    "referer": "https://docs.example.com/deck",
}
SCRAPER = {"user-agent": "python-requests/2.32.3", "accept": "*/*"}
PROXY_SCRAPER = {"user-agent": "Mozilla/5.0 (compatible; Scrapy/2.11)"}


@pytest.fixture()
def asn_table(tmp_path: Path) -> Path:
    path = tmp_path / "asn.csv"
    path.write_text(
        "203.0.113.0/24,64500,Example Cloud\n"
        "198.51.100.0/24,64501,Example Transit\n",
        encoding="utf-8",
    )
    return path


# --- tokens --------------------------------------------------------------
def test_token_is_opaque_and_resolves_back_to_its_label(session):
    canary = tokens.mint(session, "pitch-deck v3 / acme")
    assert "pitch" not in canary.url
    assert "acme" not in canary.url
    row = tokens.verify(session, canary.token)
    assert row is not None and row.label == "pitch-deck v3 / acme"


def test_unknown_or_tampered_token_is_rejected(session):
    tokens.mint(session, "a")
    assert tokens.verify(session, "not-a-real-token") is None
    assert tokens.verify(session, "A" * 22) is None


def test_revoked_canary_still_answers_but_stops_recording(session):
    canary = tokens.mint(session, "revoked doc")
    assert tokens.revoke(session, canary.token)
    with pytest.raises(UnknownCanary):
        record_observation(session, token=canary.token, source_ip="203.0.113.9",
                           headers=SCRAPER)


def test_each_mint_is_unique(session):
    a = tokens.mint(session, "same label")
    b = tokens.mint(session, "same label")
    assert a.token != b.token


# --- fingerprinting -----------------------------------------------------
def test_scripted_client_is_flagged_as_automated():
    fp = fingerprint(source_ip="203.0.113.9", headers=SCRAPER)
    assert fp.looks_automated
    assert any(s["signal"] == "scripted_user_agent" for s in fp.extraction_signals)


def test_a_normal_browser_is_not_flagged():
    fp = fingerprint(source_ip="203.0.113.9", headers=BROWSER)
    assert not fp.looks_automated
    assert fp.client_family == "browser-chromium"


def test_raw_address_is_not_stored_by_default():
    fp = fingerprint(source_ip="203.0.113.9", headers=SCRAPER)
    assert fp.origin_raw is None
    assert len(fp.origin_hmac) == 64
    assert "203.0.113.9" not in fp.origin_hmac


def test_same_origin_hashes_stably_but_different_tools_do_not():
    requests_fp = fingerprint(source_ip="203.0.113.9", headers=SCRAPER)
    scrapy_fp = fingerprint(source_ip="203.0.113.9", headers=PROXY_SCRAPER)
    assert requests_fp.origin_hmac == scrapy_fp.origin_hmac
    # Two different collection tools must not collapse into one cluster.
    assert requests_fp.client_hash != scrapy_fp.client_hash
    assert requests_fp.client_tool == "python-requests"
    assert scrapy_fp.client_tool == "scrapy"


def test_a_version_upgrade_does_not_create_a_new_cluster():
    old = fingerprint(source_ip="203.0.113.9", headers={"user-agent": "python-requests/2.31.0"})
    new = fingerprint(source_ip="203.0.113.9", headers={"user-agent": "python-requests/2.32.3"})
    assert old.client_hash == new.client_hash


def test_asn_resolution_uses_the_local_table_only(asn_table: Path):
    fp = fingerprint(source_ip="203.0.113.9", headers=SCRAPER, asn_db=asn_table)
    assert fp.asn == 64500
    assert fp.asn_org == "Example Cloud"


def test_unlisted_address_resolves_to_nothing_rather_than_a_guess(asn_table: Path):
    fp = fingerprint(source_ip="192.0.2.7", headers=SCRAPER, asn_db=asn_table)
    assert fp.asn is None


def test_only_allowlisted_headers_are_kept():
    fp = fingerprint(
        source_ip="203.0.113.9",
        headers={**SCRAPER, "cookie": "session=secret", "authorization": "Bearer x"},
    )
    assert "cookie" not in fp.headers
    assert "authorization" not in fp.headers


# --- tarpit -------------------------------------------------------------
def test_tarpit_is_off_by_default():
    fp = fingerprint(source_ip="203.0.113.9", headers=SCRAPER)
    assert tarpit_delay_ms(fp) == 0


def test_tarpit_never_exceeds_the_hard_cap(monkeypatch):
    from phantom.config import settings

    object.__setattr__(settings, "tarpit_ms_max", 999_999)
    try:
        fp = fingerprint(source_ip="203.0.113.9", headers=SCRAPER)
        assert tarpit_delay_ms(fp) <= TARPIT_HARD_CAP_MS
    finally:
        object.__setattr__(settings, "tarpit_ms_max", 0)


def test_a_browser_is_never_tarpitted(monkeypatch):
    from phantom.config import settings

    object.__setattr__(settings, "tarpit_ms_max", 1000)
    try:
        fp = fingerprint(source_ip="203.0.113.9", headers=BROWSER)
        assert tarpit_delay_ms(fp) == 0
    finally:
        object.__setattr__(settings, "tarpit_ms_max", 0)


# --- the graph ----------------------------------------------------------
def _simulate(session, asn_table: Path) -> None:
    """Two documents, two scrapers, one shared client stack."""
    deck = tokens.mint(session, "pitch-deck v3 / acme")
    model = tokens.mint(session, "financial-model v2 / acme")
    record_observation(session, token=deck.token, source_ip="203.0.113.9",
                       headers=SCRAPER, asn_db=asn_table)
    record_observation(session, token=model.token, source_ip="203.0.113.9",
                       headers=SCRAPER, asn_db=asn_table)
    record_observation(session, token=deck.token, source_ip="203.0.113.77",
                       headers=SCRAPER, asn_db=asn_table)
    record_observation(session, token=deck.token, source_ip="198.51.100.4",
                       headers=BROWSER, asn_db=asn_table)


def test_hits_become_observed_edges(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    graph = to_cytoscape(session)
    classes = {e["data"]["classification"] for e in graph["elements"] if "relation" in e["data"]}
    assert "observed" in classes
    assert graph["stats"]["nodes"] > 0


def test_shared_client_across_origins_becomes_a_correlated_edge(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    graph = to_cytoscape(session)
    correlated = [
        e["data"] for e in graph["elements"]
        if e["data"].get("classification") == "correlated"
    ]
    assert correlated
    assert all("not people" in (e["caveat"] or "").lower() or e["caveat"] for e in correlated)


def test_two_canaries_on_one_client_become_a_capped_hypothesis(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    graph = to_cytoscape(session)
    clusters = [
        e["data"] for e in graph["elements"]
        if e["data"].get("rule_id") == "R-MIR-5"
    ]
    assert clusters, "the same scraper touching two documents is the campaign signal"
    for cluster in clusters:
        assert cluster["classification"] == "hypothesized"
        assert cluster["confidence"] <= 0.65
        assert "not proof of a common operator" in cluster["caveat"]


def test_the_counter_graph_never_contains_a_person(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    graph = to_cytoscape(session)
    kinds = {e["data"]["kind"] for e in graph["elements"] if "relation" not in e["data"]}
    assert kinds <= {"canary", "origin", "client", "asn"}
    for element in graph["elements"]:
        assert "203.0.113.9" not in str(element)


def test_building_twice_does_not_double_count(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    first = to_cytoscape(session)["stats"]["edges"]
    build(session)
    assert to_cytoscape(session)["stats"]["edges"] == first


# --- the report ---------------------------------------------------------
def test_report_names_which_copy_leaked(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    report = asymmetry_report(session)
    labels = {row["label"] for row in report["leaked_copies"]}
    assert labels == {"pitch-deck v3 / acme", "financial-model v2 / acme"}
    assert report["hits"] == 4
    assert report["automated_hits"] == 3


def test_report_states_both_sides_of_the_asymmetry(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    report = asymmetry_report(session)
    assert report["what_they_learned"]
    assert report["what_you_learned"]
    assert any("which" in line.lower() and "copies" in line.lower()
               for line in report["what_you_learned"])


def test_guardrails_are_reported_and_retaliation_is_impossible(session):
    report = asymmetry_report(session)
    guardrails = report["guardrails"]
    assert RETALIATION_ENABLED is False
    assert guardrails["retaliation_enabled"] is False
    assert guardrails["exploitation_attempted"] is False
    assert guardrails["outbound_requests_made_to_requester"] == 0
    assert guardrails["raw_ip_retained"] is False
    assert "illegal" in guardrails["why"]


def test_caveats_forbid_reading_infrastructure_as_identity(session, asn_table):
    _simulate(session, asn_table)
    build(session)
    report = asymmetry_report(session)
    joined = " ".join(report["caveats"]).lower()
    assert "not an identity" in joined
    assert "not a shared actor" in joined
    assert "proxy" in joined


def test_empty_state_is_honest(session):
    report = asymmetry_report(session)
    assert report["hits"] == 0
    assert "No canary has been touched" in report["summary"]


def test_gif_payload_is_a_real_gif():
    assert TRANSPARENT_GIF.startswith(b"GIF89a")
    assert TRANSPARENT_GIF.endswith(b";")

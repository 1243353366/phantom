"""Detection heuristics must be explainable, not merely accurate."""
from __future__ import annotations

from phantom.collector.headers import parse_eml
from phantom.collector.pixels import find_links, find_pixels


def test_one_by_one_image_is_flagged_with_reason():
    pixels = find_pixels('<img src="https://cdn.example.com/a.gif" width="1" height="1">')
    assert len(pixels) == 1
    assert any("1x1" in r or "size" in r for r in pixels[0].reasons)


def test_visible_image_is_not_a_pixel():
    assert find_pixels('<img src="https://cdn.example.com/hero.png" width="600" height="320">') == []


def test_hidden_style_is_enough_to_flag():
    pixels = find_pixels('<img src="https://a.example.com/x.gif" style="display: none">')
    assert pixels and pixels[0].is_tracking_pixel


def test_more_reasons_raise_confidence():
    weak = find_pixels('<img src="https://x.example.com/x.gif" width="1" height="1">')[0]
    strong = find_pixels(
        '<img src="https://x.example.com/open/track?utm_source=a" '
        'width="1" height="1" style="display:none">'
    )[0]
    assert strong.confidence > weak.confidence


def test_redirect_parameter_is_decoded_to_real_destination():
    link = find_links(
        '<a href="https://esp.example.com/c?url=https%3A%2F%2Fshop.example.org%2Fp">go</a>'
    )[0]
    assert link.is_redirector
    assert link.target_host == "shop.example.org"


def test_plain_link_is_not_a_redirector():
    link = find_links('<a href="https://shop.example.org/p">go</a>')[0]
    assert not link.is_redirector


def test_headers_yield_relay_chain_and_dkim_identity():
    raw = (
        "From: Acme <billing@acme-store.com>\n"
        "Date: Wed, 02 Sep 2026 14:12:00 +0000\n"
        "Message-ID: <x@y>\n"
        "DKIM-Signature: v=1; d=acme-store.com; s=k1; b=zzz\n"
        "Authentication-Results: mx.google.com; spf=pass; dmarc=pass\n"
        "Received: from mail.acme-store.com by mx.list-manage.com; Wed, 2 Sep 2026\n"
        "Content-Type: text/html\n\n"
        "<p>hi</p>"
    )
    mail = parse_eml(raw)
    assert mail.from_domain == "acme-store.com"
    assert "mx.list-manage.com" in mail.relay_hosts
    assert mail.dkim[0] == {"domain": "acme-store.com", "selector": "k1"}
    assert any(r["mechanism"] == "dmarc" and r["result"] == "pass" for r in mail.auth_results)


def test_sample_corpus_parses(sample_paths):
    assert len(sample_paths) >= 4
    for path in sample_paths:
        mail = parse_eml(path.read_bytes())
        assert mail.from_domain
        assert mail.message_id

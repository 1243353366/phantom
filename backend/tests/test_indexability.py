"""Two directives, kept apart: guidance about fetching and guidance about indexing."""
from __future__ import annotations

from phantom.exposure.indexability import (
    INDEXABLE,
    NOT_INDEXABLE,
    UNVERIFIABLE,
    directives_from_header,
    directives_from_html,
    is_allowed,
    verdict,
)

# --- robots.txt parsing, RFC 9309 ------------------------------------------

def test_a_disallowed_path_is_blocked_and_a_sibling_is_not():
    robots = "User-agent: *\nDisallow: /private"
    assert is_allowed(robots, "/private/x")[0] is False
    assert is_allowed(robots, "/public")[0] is True


def test_the_longer_match_wins_a_tie_in_the_other_direction():
    robots = "User-agent: *\nDisallow: /private\nAllow: /private/ok"
    allowed, reason = is_allowed(robots, "/private/ok/page")
    assert allowed is True
    assert "Allow" in reason


def test_wildcards_and_end_anchors_match_as_specified():
    robots = "User-agent: *\nDisallow: /*.pdf$"
    assert is_allowed(robots, "/docs/a.pdf")[0] is False
    # The anchor means the query string is a different path.
    assert is_allowed(robots, "/docs/a.pdf?v=2")[0] is True


def test_an_empty_disallow_means_no_restriction():
    assert is_allowed("User-agent: *\nDisallow:\n", "/anything")[0] is True


def test_a_named_group_beats_the_wildcard_group():
    robots = "User-agent: *\nDisallow: /\n\nUser-agent: googlebot\nDisallow: /nope"
    assert is_allowed(robots, "/anything")[0] is False
    assert is_allowed(robots, "/anything", agent="googlebot")[0] is True


def test_comments_and_blank_lines_are_tolerated():
    robots = "# hello\nUser-agent: *   # everyone\n\nDisallow: /secret  # keep out\n"
    assert is_allowed(robots, "/secret/1")[0] is False
    assert is_allowed(robots, "/open")[0] is True


# --- directives -------------------------------------------------------------

def test_meta_robots_is_read_case_insensitively():
    html = '<meta name="ROBOTS" content="NOINDEX, follow">'
    assert directives_from_html(html) == ["noindex", "follow"]


def test_other_meta_tags_are_ignored():
    assert directives_from_html('<meta name="description" content="noindex">') == []


def test_x_robots_tag_header_is_read():
    assert directives_from_header("noindex, nofollow") == ["noindex", "nofollow"]
    assert directives_from_header(None) == []


# --- the verdict ------------------------------------------------------------

def test_allowed_and_clean_means_indexable():
    found = verdict(url="https://x.test/", robots_text=None, robots_status=404,
                    html="<html></html>")
    assert found.indexable == INDEXABLE
    assert found.crawl_allowed is True


def test_allowed_with_noindex_means_not_indexable():
    found = verdict(url="https://x.test/a", robots_text="User-agent: *\nDisallow:",
                    robots_status=200, html='<meta name="robots" content="noindex">')
    assert found.indexable == NOT_INDEXABLE
    assert "recrawl" in found.caveat


def test_a_disallow_that_hides_noindex_is_reported_as_unverifiable():
    """The trap: the crawler never fetches the page, so the tag is never read."""
    found = verdict(
        url="https://x.test/private",
        robots_text="User-agent: *\nDisallow: /private",
        robots_status=200,
        html='<meta name="robots" content="noindex">',
        path="/private",
    )
    assert found.crawl_allowed is False
    assert found.indexable == UNVERIFIABLE
    assert "not an indexing directive" in found.reason
    assert "allow the crawl" in found.caveat


def test_a_server_error_on_robots_is_treated_as_disallow():
    found = verdict(url="https://x.test/", robots_text=None, robots_status=503)
    assert found.crawl_allowed is False
    assert found.indexable == UNVERIFIABLE


def test_the_x_robots_header_alone_is_enough():
    found = verdict(url="https://x.test/a", robots_text="", robots_status=200,
                    x_robots_tag="noindex")
    assert found.noindex_declared is True
    assert found.indexable == NOT_INDEXABLE


def test_the_three_answers_stay_separate():
    """A private-looking config must not be reported as one confident verdict."""
    found = verdict(url="https://x.test/", robots_text="User-agent: *\nDisallow: /",
                    robots_status=200, html="")
    assert found.crawl_allowed is False
    assert found.noindex_declared is False
    assert found.indexable == UNVERIFIABLE

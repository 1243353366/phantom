"""The six questions, and the two rules that keep them honest.

Every question either reports local findings or says it has not been measured.
Nothing is invented to fill a gap, and no finding may describe another person.
"""
from __future__ import annotations

import json

from phantom.exposure.posture import (
    ANSWERED,
    CRAWLERS,
    IDENTIFIERS,
    LINKAGE,
    NO_ACCESS,
    NOT_MEASURED,
    REMEDIATION,
    SITES,
    build,
)


def _answers(session, **kwargs):
    return {row["id"]: row for row in build(session, **kwargs)["questions"]}


def _populate(session, *, handle="aadi.s", email="aadi@example.com", community=True):
    from phantom.inventory import store
    from phantom.inventory.facets import Facet, Reading

    facets = [Facet("handle", handle, "username"), Facet("email", email, "email")]
    if community:
        facets.append(Facet("community", "Privacy Tooling", "servers/index.csv:name"))
    store.record(session, Reading(platform="discord", facets=facets), source_ref="inv:d")
    store.record(session, Reading(platform="meta", facets=list(facets)), source_ref="inv:m")
    store.project(session)


def test_an_empty_install_admits_it_has_nothing(session):
    answers = _answers(session)
    assert answers[NO_ACCESS]["status"] != ANSWERED
    assert answers[SITES]["status"] == NOT_MEASURED
    assert answers[REMEDIATION]["findings"] == []
    assert build(session)["actions_total"] == 0


def test_two_platforms_with_one_email_and_handle(session):
    _populate(session)
    answers = _answers(session)

    assert answers[LINKAGE]["status"] == ANSWERED
    assert answers[IDENTIFIERS]["status"] == ANSWERED
    assert any("email is attached to 2 accounts" in f for f in answers[IDENTIFIERS]["findings"])

    actions = " ".join(answers[REMEDIATION]["findings"])
    assert "per-platform alias" in actions
    assert "distinct handle" in actions


def test_identifiers_are_never_printed_in_the_clear(session):
    _populate(session)
    rendered = json.dumps(build(session))
    assert "aadi@example.com" not in rendered
    # The handle is public and is meant to appear; the contact value is not.
    assert "aadi.s" in rendered


def test_what_a_stranger_sees_uses_only_published_fields(session):
    _populate(session)
    answers = _answers(session)
    findings = " ".join(answers[NO_ACCESS]["findings"])
    assert "without any access" in findings
    assert "Privacy Tooling" in findings


def test_crawler_question_is_unmeasured_without_a_saved_run(session):
    assert _answers(session)[CRAWLERS]["status"] == NOT_MEASURED


def test_a_saved_indexability_run_feeds_the_crawler_and_remediation(session):
    saved = [
        {"url": "https://a.test/x", "indexable": "yes", "crawl_allowed": True},
        {"url": "https://a.test/y", "indexable": "unverifiable", "crawl_allowed": False},
    ]
    answers = _answers(session, indexability=saved)

    assert answers[CRAWLERS]["status"] == ANSWERED
    crawl = " ".join(answers[CRAWLERS]["findings"])
    assert "may still be indexed" in crawl

    actions = " ".join(answers[REMEDIATION]["findings"])
    assert "serve noindex" in actions
    assert "URL inspector" in actions


def test_every_question_names_what_it_cannot_see(session):
    _populate(session)
    for row in build(session)["questions"]:
        assert row["cannot_see"], row["id"]


def test_the_thesis_travels_with_the_output(session):
    rendered = build(session)["thesis"]
    assert "operator's own data" in rendered
    assert "no question is answered by examining anyone else" in rendered

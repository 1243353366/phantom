"""Pins for the stitching and attention boundaries, from the 2026-11-01 audit.

Each test names the property it holds, because a passing suite that does not test
a boundary is not evidence about the boundary.
"""
from __future__ import annotations

import datetime as dt
import json

from phantom import attention
from phantom.inventory import report, store
from phantom.inventory.adapters import MetaExport
from phantom.inventory.facets import Facet, Reading

# --- 1. denied keys, at every depth ---------------------------------------

def _meta(tmp_path, payload):
    root = tmp_path / "m"
    inner = root / "personal_information" / "personal_information"
    inner.mkdir(parents=True)
    (inner / "personal_information.json").write_text(json.dumps(payload), encoding="utf-8")
    return root


def test_a_denied_key_inside_a_container_is_refused_at_depth(tmp_path):
    reading = MetaExport(_meta(tmp_path, {
        "profile_v2": {"username": "aadi.s", "followers": ["x"]},
    })).read()
    assert any("followers" in r.item for r in reading.refusals)


def test_a_denied_key_nested_inside_an_allowed_facet_subtree_is_refused(tmp_path):
    """The subtree is allowed; the denied key inside it is still refused."""
    reading = MetaExport(_meta(tmp_path, {
        "profile_v2": {"emails": {"emails": ["a@b.c"], "friends": ["someone"]}},
    })).read()
    assert any("friends" in r.item for r in reading.refusals)
    assert [f.value for f in reading.facets if f.kind == "email"] == ["a@b.c"]


def test_an_unreached_denied_key_yields_nothing_and_is_not_reported(tmp_path):
    """A branch that is never traversed cannot leak, and is not claimed as read.

    The refusal list is a record of what was *encountered and declined*. A key
    inside a subtree the walk never enters is inert; saying it was "refused" would
    overstate what the adapter examined.
    """
    reading = MetaExport(_meta(tmp_path, {
        "profile_v2": {"username": "aadi.s", "everything_else": {"messages": ["x"]}},
    })).read()
    assert [f.value for f in reading.facets] == ["aadi.s"]
    assert all("messages" not in r.item for r in reading.refusals)


# --- 2. normalisation, consistent across platforms ------------------------

def test_email_case_and_padding_never_split_a_match():
    assert Facet("email", " Aadi@Example.COM ", "").normalised == "aadi@example.com"


def test_phone_punctuation_is_removed_so_one_number_matches_itself():
    variants = ["+1 (555) 010-0100", "+15550100100", "+1-555-010-0100", "+1.555.010.0100"]
    assert len({Facet("phone", v, "").normalised for v in variants}) == 1


def test_a_country_code_is_never_inferred_onto_a_number():
    """`5550100` is not assumed to be `+15550100`: that would be an inference."""
    national = Facet("phone", "5550100100", "").normalised
    international = Facet("phone", "+15550100100", "").normalised
    assert national != international


def test_a_handle_ignores_whitespace_underscores_and_hyphens_only():
    assert Facet("handle", "Aadi_S", "").normalised == Facet("handle", "aadi-s", "").normalised
    # A dot is not a separator: collapsing it would join distinct people on a guess.
    assert Facet("handle", "aadi.s", "").normalised != Facet("handle", "aadis", "").normalised


# --- 3 and 4. provenance, and observed vs correlated ----------------------

def _two_platforms(session, *, same_handle=False, same_email=True):
    store.record(session, Reading(platform="discord", facets=[
        Facet("handle", "aadi.s", "username"),
        Facet("email", "aadi@example.com", "email"),
    ]), source_ref="inventory:discord")
    store.record(session, Reading(platform="meta", facets=[
        Facet("handle", "aadi.s" if same_handle else "aadishankar", "username"),
        Facet("email", "aadi@example.com" if same_email else "other@example.com", "email"),
    ]), source_ref="inventory:meta")
    store.project(session)
    return report.build(session)


def test_a_shared_email_is_reported_as_an_observed_identifier_join(session):
    cluster = _two_platforms(session)["clusters"][0]
    assert cluster["link"] == "shared_identifier"
    assert cluster["link_class"] == "observed"
    assert [row["identifier_kind"] for row in cluster["evidence"]] == ["email"]


def test_a_reused_handle_alone_is_reported_as_correlated(session):
    cluster = _two_platforms(session, same_handle=True, same_email=False)["clusters"][0]
    assert cluster["link"] == "reused_handle"
    assert cluster["link_class"] == "correlated"


def test_both_kinds_of_link_are_kept_apart_in_one_cluster(session):
    cluster = _two_platforms(session, same_handle=True)["clusters"][0]
    assert cluster["link"] == "shared_identifier_and_handle"
    assert {row["rule"] for row in cluster["evidence"]} == {"R-INV-1", "R-INV-2"}


def test_every_matching_identifier_keeps_its_source(session):
    cluster = _two_platforms(session, same_handle=True)["clusters"][0]
    for row in cluster["evidence"]:
        assert row["source_refs"], row
        assert row["confidence"] > 0
        assert row["platforms"] == ["discord", "meta"]


def test_a_shared_value_is_never_presented_as_proof_of_ownership(session):
    cluster = _two_platforms(session)["clusters"][0]
    assert "does not prove one person controls them" in cluster["not_proof_of_ownership"]
    assert cluster["confidence"] < 1.0


def test_one_platform_alone_is_not_stitchable(session):
    store.record(session, Reading(platform="discord", facets=[
        Facet("handle", "aadi.s", "username"), Facet("email", "a@b.c", "email"),
    ]), source_ref="inventory:discord")
    store.project(session)
    cluster = report.build(session)["clusters"][0]
    assert cluster["stitchable"] is False
    assert cluster["link"] == "none"


# --- 5. the attention counter, at its edges ------------------------------

def _attention(tmp_path, monkeypatch):
    monkeypatch.setattr(attention, "log_path", lambda: tmp_path / "a.jsonl")
    monkeypatch.setattr(attention, "budget_path", lambda: tmp_path / "b.json")
    return tmp_path / "a.jsonl"


def test_exactly_the_gap_threshold_is_not_a_break(tmp_path, monkeypatch):
    _attention(tmp_path, monkeypatch)
    base = dt.datetime.now(dt.UTC).replace(hour=9, minute=0, second=0, microsecond=0)
    attention.record("graph", at=base)
    attention.record("graph", at=base + dt.timedelta(minutes=20))
    assert attention.summary(now=base + dt.timedelta(hours=1))["longest_sitting_minutes"] == 20.0


def test_one_second_past_the_threshold_is_a_break(tmp_path, monkeypatch):
    _attention(tmp_path, monkeypatch)
    base = dt.datetime.now(dt.UTC).replace(hour=9, minute=0, second=0, microsecond=0)
    attention.record("graph", at=base)
    attention.record("graph", at=base + dt.timedelta(minutes=20, seconds=1))
    # Each look is its own sitting, so the longest sitting is zero minutes.
    assert attention.summary(now=base + dt.timedelta(hours=1))["longest_sitting_minutes"] == 0.0


def test_a_clock_that_jumps_backwards_does_not_erase_a_sitting(tmp_path, monkeypatch):
    _attention(tmp_path, monkeypatch)
    base = dt.datetime.now(dt.UTC).replace(hour=9, minute=0, second=0, microsecond=0)
    attention.record("graph", at=base + dt.timedelta(minutes=30))
    attention.record("graph", at=base)  # clock correction
    result = attention.summary(now=base + dt.timedelta(hours=1))
    assert result["longest_sitting_minutes"] == 30.0


def test_a_naive_timestamp_does_not_crash_the_command(tmp_path, monkeypatch):
    log = _attention(tmp_path, monkeypatch)
    log.write_text(
        '{"at": "2026-11-01T09:00:00", "command": "graph"}\n'
        '{"at": "2026-11-01T09:10:00+00:00", "command": "graph"}\n',
        encoding="utf-8",
    )
    result = attention.summary(now=dt.datetime(2026, 11, 1, 12, tzinfo=dt.UTC))
    assert result["checks_today"] == 2
    assert result["longest_sitting_minutes"] == 10.0


def test_a_restart_keeps_the_sitting(tmp_path, monkeypatch):
    """The log is the state: a new process measures the same sitting."""
    _attention(tmp_path, monkeypatch)
    base = dt.datetime.now(dt.UTC).replace(hour=9, minute=0, second=0, microsecond=0)
    attention.record("graph", at=base)
    attention.record("graph", at=base + dt.timedelta(minutes=15))
    # Re-read from disk exactly as a fresh process would.
    fresh = attention.entries()
    assert len(fresh) == 2
    assert attention.summary(now=base + dt.timedelta(hours=1))["longest_sitting_minutes"] == 15.0


def test_a_breach_is_described_as_a_threshold_not_a_condition(tmp_path, monkeypatch):
    _attention(tmp_path, monkeypatch)
    attention.set_budget(checks_per_day=1)
    for _ in range(3):
        attention.record("graph")
    result = attention.summary()
    assert result["over_budget"] is True
    assert "not a diagnosis" in result["note"]
    assert "does not mean there is a problem" in result["note"]

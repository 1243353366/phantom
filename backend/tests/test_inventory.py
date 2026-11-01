"""Own-account inventory: what it reads, what it refuses, what it links.

The refusals carry the weight here. An inventory that quietly absorbed a friends
list would be the social graph this project declined to build, arriving through
a file path instead of an API.
"""
from __future__ import annotations

import json

import pytest

from phantom.inventory.adapters import DiscordExport, ExportNotFound
from phantom.inventory.report import build as report

SAMPLES = __import__("pathlib").Path(__file__).resolve().parents[2] / "samples" / "inventory"


def _package(tmp_path, *, user=None, extra_files=None):
    package = tmp_path / "discord-package"
    (package / "account").mkdir(parents=True)
    payload = user if user is not None else {
        "id": "42",
        "username": "aadi.s",
        "email": "aadi@example.com",
        "phone": "+15550100",
    }
    (package / "account" / "user.json").write_text(json.dumps(payload), encoding="utf-8")
    for name, text in (extra_files or {}).items():
        target = package / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return package


# --- refusals ---------------------------------------------------------------

def test_pointing_at_a_messages_file_is_refused(tmp_path):
    path = tmp_path / "messages.csv"
    path.write_text("channel,timestamp,content\n", encoding="utf-8")
    with pytest.raises(ExportNotFound, match="not an account file"):
        DiscordExport(path).read()


def test_a_friends_list_is_refused_and_reported(tmp_path):
    package = _package(tmp_path, user={
        "id": "1", "username": "aadi", "email": "a@example.com",
        "friends": [{"username": "someone-else"}],
    })
    reading = DiscordExport(package).read()
    assert any("friends" in r.item for r in reading.refusals)
    assert all(f.kind != "friend" for f in reading.facets)


def test_other_people_in_the_package_are_never_opened(tmp_path):
    package = _package(tmp_path, extra_files={
        "messages/index.csv": "channel,timestamp,content\n1,2,someone said something\n",
        "servers/index.csv": "id,name\n1,a server\n",
    })
    reading = DiscordExport(package).read()
    refused = [r.item for r in reading.refusals]
    assert "messages/index.csv" in refused
    # The servers file carries communities, which are the operator's own, so it is
    # read by a name-only reader and its blanket refusal is cleared.
    assert "servers/index.csv" not in refused
    assert [f.value for f in reading.facets if f.kind == "community"] == ["a server"]


def test_a_member_column_makes_the_servers_file_unreadable(tmp_path):
    package = _package(tmp_path, extra_files={
        "servers/index.csv": "id,name,members\n1,a server,\"someone,someone-else\"\n",
    })
    reading = DiscordExport(package).read()
    assert any("members" in r.reason for r in reading.refusals)
    assert all(f.kind != "community" for f in reading.facets)


def test_the_sample_package_reads_only_the_operator(tmp_path):
    reading = DiscordExport(SAMPLES / "discord").read()
    kinds = sorted({f.kind for f in reading.facets})
    # community joins the list because servers/index.csv is now read, name only.
    assert kinds == ["account_id", "community", "email", "handle", "phone"]
    assert any("friends" in r.item for r in reading.refusals)


def test_an_account_file_with_nothing_recognisable_stores_nothing(tmp_path):
    package = _package(tmp_path, user={"global_name": "Aadi", "verified": True})
    with pytest.raises(ExportNotFound, match="none of the expected fields"):
        DiscordExport(package).read()


# --- what gets stored -------------------------------------------------------

def test_no_contact_value_is_stored_in_the_clear(session, tmp_path):
    from phantom.inventory import store

    reading = DiscordExport(_package(tmp_path)).read()
    row = store.record(session, reading)
    payload = json.dumps(row.payload)
    assert "aadi@example.com" not in payload
    assert "15550100" not in payload
    # Separators are only whitespace, underscores and hyphens: a dot is kept,
    # because "aadi.s" and "aadis" are not the same string and joining them
    # would be a guess this layer is not allowed to make.
    assert row.payload["handle"] == "aadi.s"


def test_one_identifier_listed_twice_is_one_fact(session, tmp_path):
    from phantom.inventory import store

    reading = DiscordExport(_package(tmp_path, user={
        "username": "aadi", "email": "a@example.com",
        "user": {"email": "A@Example.com"},
    })).read()
    payload = store.to_payload(reading)
    emails = [i for i in payload["identifiers"] if i["kind"] == "email"]
    assert len(emails) == 1


def test_an_inventory_payload_may_not_smuggle_new_fields(session):
    from phantom import observations

    with pytest.raises(ValueError, match="unexpected observation fields"):
        observations.store(
            session,
            source_kind=observations.ACCOUNT_INVENTORY,
            source_ref="inventory:test",
            payload={"platform": "discord", "friends": ["someone"]},
        )


# --- consent ----------------------------------------------------------------

def test_import_needs_its_own_platform_opt_in(session):
    from phantom.auth.consent import ConsentError, ConsentService

    service = ConsentService(session)
    service.enroll(
        gmail_address="aadi@example.com", consent_gmail=True,
        attested_by="aadi", attestation="my mailbox",
    )
    with pytest.raises(ConsentError, match="no active consent covers 'discord'"):
        service.require_platform("discord")

    service.enroll(
        platforms=["discord"], attested_by="aadi", attestation="my own account export",
    )
    service.require_platform("discord")
    assert service.platforms_authorised() == {"discord"}


# --- what it links ---------------------------------------------------------

def _two_platforms(session):
    from phantom.inventory import store
    from phantom.inventory.facets import Facet, Reading

    store.record(session, Reading(platform="discord", facets=[
        Facet("handle", "aadi.s", "username"),
        Facet("email", "aadi@example.com", "email"),
    ]), source_ref="inventory:discord")
    store.record(session, Reading(platform="forum", facets=[
        Facet("handle", "aadi.s", "username"),
        Facet("email", "aadi@example.com", "email"),
    ]), source_ref="inventory:forum")
    return store.project(session)


def test_the_same_handle_is_a_correlation_not_an_observation(session):
    from sqlalchemy import select

    from phantom.models import Edge

    _two_platforms(session)
    reuse = [e for e in session.scalars(select(Edge)) if e.rule_id == "R-INV-2"]
    assert len(reuse) == 1
    assert reuse[0].classification == "correlated"
    assert "not a verified identity" in reuse[0].caveat


def test_a_shared_identifier_joins_two_accounts(session):
    result = report(session) if _two_platforms(session) else {}
    assert result["accounts"] == 2
    assert result["clusters"][0]["stitchable"] is True
    assert result["findings"]


def test_different_handles_are_not_joined(session):
    from phantom.inventory import store
    from phantom.inventory.facets import Facet, Reading

    store.record(session, Reading(platform="discord", facets=[Facet("handle", "aadi.s", "username")]),
                 source_ref="inventory:d")
    store.record(session, Reading(platform="forum", facets=[Facet("handle", "someone-else", "username")]),
                 source_ref="inventory:f")
    store.project(session)

    result = report(session)
    assert result["accounts"] == 2
    assert result["clusters"][0]["stitchable"] is False


def test_the_inventory_rebuilds_from_raw_observations(session):
    from phantom import rebuild

    _two_platforms(session)
    before = rebuild.graph_digest(session)
    rebuild.rebuild(session)
    assert rebuild.graph_digest(session) == before


def test_the_report_says_when_nothing_is_imported(session):
    assert report(session)["findings"] == []


# --- Meta, the second platform ---------------------------------------------

from phantom.inventory.adapters import MetaExport  # noqa: E402


def _meta_export(tmp_path, *, profile=None, extra=None):
    root = tmp_path / "meta-export"
    inner = root / "personal_information" / "personal_information"
    inner.mkdir(parents=True)
    payload = {
        "profile_v2": profile if profile is not None else {
            "name": {"name": "Aadi Shankar"},
            "emails": {"emails": ["aadi@example.com"]},
            "phone_numbers": ["+15550100"],
            "username": "aadi.s",
        }
    }
    (inner / "personal_information.json").write_text(json.dumps(payload), encoding="utf-8")
    for name in (extra or []):
        (root / name).mkdir(parents=True, exist_ok=True)
    return root


def test_meta_reads_identity_from_the_nested_export(tmp_path):
    reading = MetaExport(_meta_export(tmp_path)).read()
    kinds = sorted({f.kind for f in reading.facets})
    assert kinds == ["email", "handle", "phone"]


def test_meta_does_not_read_the_display_name(tmp_path):
    reading = MetaExport(_meta_export(tmp_path)).read()
    assert all("Aadi Shankar" not in f.value for f in reading.facets)


def test_meta_refuses_the_followers_directory(tmp_path):
    root = _meta_export(tmp_path, extra=["followers_and_following", "messages"])
    reading = MetaExport(root).read()
    refused = " ".join(r.item for r in reading.refusals)
    assert "followers_and_following" in refused
    assert "messages" in refused


def test_meta_refuses_a_friends_key_inside_the_profile(tmp_path):
    root = _meta_export(tmp_path, profile={
        "username": "aadi.s",
        "friends": ["someone-else"],
        "emails": {"emails": ["aadi@example.com"]},
    })
    reading = MetaExport(root).read()
    assert any("friends" in r.item for r in reading.refusals)
    assert all(f.kind != "handle" or f.value == "aadi.s" for f in reading.facets)


def test_two_platforms_stitch_through_a_shared_email(session):
    """The point of the layer: two accounts, joined by something already published."""
    from phantom.inventory import store
    from phantom.inventory.facets import Facet, Reading

    store.record(session, Reading(platform="discord", facets=[
        Facet("handle", "aadi.s", "username"),
        Facet("email", "aadi@example.com", "email"),
    ]), source_ref="inventory:discord")
    store.record(session, Reading(platform="meta", facets=[
        Facet("handle", "aadishankar", "username"),
        Facet("email", "aadi@example.com", "email"),
    ]), source_ref="inventory:meta")
    store.project(session)

    result = report(session)
    assert result["accounts"] == 2
    # Different handles, so R-INV-2 does not fire: the email is what joins them.
    assert result["clusters"][0]["stitchable"] is True
    assert result["clusters"][0]["joined_by"] == []
    assert result["findings"]

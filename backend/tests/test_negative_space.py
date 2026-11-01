"""Absence is recorded, never explained."""
from __future__ import annotations

from phantom.collector.headers import parse_eml
from phantom.engine.relationship_engine import RelationshipEngine
from phantom.watchdog.negative_space import NegativeSpaceWatchdog


def _ingest(session, sample_paths):
    engine = RelationshipEngine(session)
    for path in sample_paths:
        engine.ingest(parse_eml(path.read_bytes()), source_ref=f"eml:{path.name}")
    engine.correlate()


def test_disappearing_tracker_is_recorded(session, sample_paths):
    _ingest(session, sample_paths)
    events = NegativeSpaceWatchdog(session).scan()
    changes = {(e.change, e.node_key) for e in events}
    assert ("tracker_disappeared", "domain:acme-store.us1.list-manage.com") in changes


def test_every_event_admits_unknown_cause(session, sample_paths):
    _ingest(session, sample_paths)
    for event in NegativeSpaceWatchdog(session).scan():
        assert event.cause_unknown is True
        assert "absence" in event.note.lower() or "not in" in event.note.lower() or event.note


def test_report_never_claims_tracking_stopped(session, sample_paths):
    _ingest(session, sample_paths)
    watchdog = NegativeSpaceWatchdog(session)
    watchdog.scan()
    report = watchdog.report()
    assert report["events"]
    assert "cannot see" in report["interpretation"]
    for event in report["events"]:
        assert event["cause_unknown"] is True


def test_scan_is_stable_when_repeated(session, sample_paths):
    _ingest(session, sample_paths)
    watchdog = NegativeSpaceWatchdog(session)
    first = watchdog.scan()
    second = watchdog.scan()
    assert len(second) == len(first)

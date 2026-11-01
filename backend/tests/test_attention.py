"""The attention budget measures this tool's draw, and refuses to measure anything else."""
from __future__ import annotations

import datetime as dt

import pytest

from phantom import attention


def test_a_view_is_recorded_and_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(attention, "log_path", lambda: tmp_path / "attention.jsonl")
    monkeypatch.setattr(attention, "budget_path", lambda: tmp_path / "budget.json")
    attention.record("shadow-report")
    attention.record("graph")
    result = attention.summary()
    assert result["checks_today"] == 2
    assert result["commands_today"] == {"shadow-report": 1, "graph": 1}


def test_anything_outside_the_allowlist_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(attention, "log_path", lambda: tmp_path / "attention.jsonl")
    with pytest.raises(ValueError, match="accepts only PHANTOM view commands"):
        attention.record("instagram-usage")


def test_a_busy_day_earns_a_nudge(tmp_path, monkeypatch):
    monkeypatch.setattr(attention, "log_path", lambda: tmp_path / "attention.jsonl")
    monkeypatch.setattr(attention, "budget_path", lambda: tmp_path / "budget.json")
    attention.set_budget(checks_per_day=3)
    for _ in range(5):
        attention.record("mirror-report")
    result = attention.summary()
    assert result["over_budget"] is True
    assert "past the 3 you set" in result["nudges"][0]


def test_a_quiet_day_gets_no_nudge(tmp_path, monkeypatch):
    monkeypatch.setattr(attention, "log_path", lambda: tmp_path / "attention.jsonl")
    monkeypatch.setattr(attention, "budget_path", lambda: tmp_path / "budget.json")
    attention.record("graph")
    result = attention.summary()
    assert result["over_budget"] is False
    assert result["nudges"] == []


def test_a_sitting_is_measured_and_a_gap_ends_it(tmp_path, monkeypatch):
    monkeypatch.setattr(attention, "log_path", lambda: tmp_path / "attention.jsonl")
    monkeypatch.setattr(attention, "budget_path", lambda: tmp_path / "budget.json")
    # Anchored to 09:00 UTC so the four hour jump cannot cross midnight and be
    # filtered out as "not today".
    base = dt.datetime.now(dt.UTC).replace(hour=9, minute=0, second=0, microsecond=0)
    for minutes in (0, 20, 40):
        attention.record("graph", at=base + dt.timedelta(minutes=minutes))
    # A four hour gap means the afternoon is a separate sitting, not one long one.
    attention.record("graph", at=base + dt.timedelta(hours=4))
    result = attention.summary(now=base + dt.timedelta(hours=4, minutes=1))
    assert result["longest_sitting_minutes"] == 40.0


def test_the_summary_says_what_it_cannot_see(tmp_path, monkeypatch):
    monkeypatch.setattr(attention, "log_path", lambda: tmp_path / "attention.jsonl")
    monkeypatch.setattr(attention, "budget_path", lambda: tmp_path / "budget.json")
    result = attention.summary()
    assert "not a health measurement" in result["note"]
    assert "no screen time" in result["note"].lower()
    assert result["checks_today"] == 0


def test_a_damaged_log_does_not_break_the_summary(tmp_path, monkeypatch):
    log = tmp_path / "attention.jsonl"
    log.write_text("{not json}\n\n" + '{"at": "bad", "command": "graph"}\n', encoding="utf-8")
    monkeypatch.setattr(attention, "log_path", lambda: log)
    monkeypatch.setattr(attention, "budget_path", lambda: tmp_path / "budget.json")
    assert attention.summary()["checks_today"] == 0

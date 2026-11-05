"""Four things that were true of this service before this round, and are not now.

Each test names the failure it pins, because a ceiling with no test is a comment.
"""
from __future__ import annotations

import stat
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from phantom import egress
from phantom.api.schemas import MAX_CONTACTS_CSV_CHARS, MAX_EMAIL_CHARS, ExposureRequest, IngestRequest
from phantom.db import _tighten


def test_the_database_is_not_world_readable(tmp_path: Path) -> None:
    """SQLite makes files 0644. This database holds who contacted whom."""
    db = tmp_path / "phantom.db"
    db.write_bytes(b"")
    db.chmod(0o644)
    (tmp_path / "phantom.db-wal").write_bytes(b"")
    (tmp_path / "phantom.db-wal").chmod(0o644)

    _tighten(db)

    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "phantom.db-wal").stat().st_mode) == 0o600


def test_the_egress_log_rotates_instead_of_growing_forever(tmp_path: Path, monkeypatch) -> None:
    """An attacker who can trigger requests could fill the disk with audit entries."""

    class Shim:
        egress_log = tmp_path / "egress.jsonl"

    monkeypatch.setattr(egress, "settings", Shim)
    Shim.egress_log.write_text("x" * (egress.LOG_MAX_BYTES + 1), encoding="utf-8")

    egress._record("https://example.com/", "test", allowed=True)

    rotated = tmp_path / "egress.jsonl.1"
    assert rotated.exists(), "the previous generation is kept"
    assert Shim.egress_log.stat().st_size < 4096, "and the live file starts over"


def test_a_response_larger_than_the_ceiling_is_refused(monkeypatch) -> None:
    """An allowlisted name is not a promise about how much it will send."""
    monkeypatch.setattr(egress, "check", lambda url: {})
    chunk = b"x" * 1024
    consumed = {"chunks": 0}

    class FakeResponse:
        status_code = 200
        headers = {"content-type": "text/plain"}
        request = httpx.Request("GET", "https://example.com/")

        def iter_bytes(self):
            for _ in range(egress.MAX_RESPONSE_BYTES // len(chunk) + 10):
                consumed["chunks"] += 1
                yield chunk

    class FakeStream:
        def __enter__(self):
            return FakeResponse()

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(egress.httpx, "stream", lambda *a, **k: FakeStream())

    with pytest.raises(egress.ResponseTooLarge):
        egress.request("GET", "https://example.com/", purpose="test")

    assert consumed["chunks"] < egress.MAX_RESPONSE_BYTES // len(chunk) + 10, "the read stopped early"


def test_an_oversized_message_is_refused_not_truncated() -> None:
    """A truncated message would parse into a graph that quietly omits evidence."""
    with pytest.raises(ValidationError):
        IngestRequest(raw_email="x" * (MAX_EMAIL_CHARS + 1))

    with pytest.raises(ValidationError):
        ExposureRequest(contacts_csv="x" * (MAX_CONTACTS_CSV_CHARS + 1))

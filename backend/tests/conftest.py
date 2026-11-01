"""Test harness. Every test runs against a throwaway database and a throwaway key."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="phantom-test-"))
os.environ.setdefault("PHANTOM_HOME", str(_TMP))
os.environ["PHANTOM_DB_URL"] = f"sqlite:///{_TMP / 'test.db'}"

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SAMPLES = ROOT.parent / "samples"

import pytest  # noqa: E402


@pytest.fixture()
def session():
    from phantom.db import Base, SessionLocal, engine

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def sample_paths():
    return sorted(SAMPLES.glob("*.eml"))

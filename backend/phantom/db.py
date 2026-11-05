"""Database session management (SQLite by default, Postgres if configured)."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from phantom.config import settings


def _sqlite_path(url: str) -> Path | None:
    if not url.startswith("sqlite"):
        return None
    path = url.replace("sqlite:///", "")
    if not path or path == ":memory:":
        return None
    return Path(path).expanduser()


def _tighten(path: Path) -> None:
    """0600 on the database and its sidecars.

    SQLite creates files 0644 under the usual umask, which makes a database of who
    contacted whom readable by every account on the machine. The key file was already
    locked down; the data was not.
    """
    for name in (path.name, path.name + "-wal", path.name + "-shm"):
        candidate = path.with_name(name)
        if candidate.exists():
            try:
                candidate.chmod(0o600)
            except OSError:
                pass


class Base(DeclarativeBase):
    pass


def _engine():
    url = settings.db_url
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        path = url.replace("sqlite:///", "")
        if path and path != ":memory:":
            Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


engine = _engine()
_DB_PATH = _sqlite_path(settings.db_url)
if _DB_PATH is not None:

    @event.listens_for(engine, "connect")
    def _lock_down(dbapi_connection, _record):  # noqa: ANN001
        # WAL and shared-memory files appear on connect, after any check at startup.
        _tighten(_DB_PATH)


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


_initialized = False


def init_db() -> None:
    """Create tables if they are missing. Safe to call repeatedly."""
    global _initialized
    if _initialized:
        return
    if _DB_PATH is not None:
        _tighten(_DB_PATH)
    from phantom import models  # noqa: F401  (register mappers)
    from phantom.shadow import models as shadow_models  # noqa: F401

    Base.metadata.create_all(engine)
    _initialized = True


def get_session() -> Session:
    init_db()
    return SessionLocal()

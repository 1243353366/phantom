"""Database session management (SQLite by default, Postgres if configured)."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from phantom.config import settings


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
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, class_=Session)


_initialized = False


def init_db() -> None:
    """Create tables if they are missing. Safe to call repeatedly."""
    global _initialized
    if _initialized:
        return
    from phantom import models  # noqa: F401  (register mappers)
    from phantom.shadow import models as shadow_models  # noqa: F401

    Base.metadata.create_all(engine)
    _initialized = True


def get_session() -> Session:
    init_db()
    return SessionLocal()

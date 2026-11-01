"""Canary tokens.

A token is an opaque, unguessable handle bound locally to a label. The label is
never encoded in the URL, so an attacker who sees the URL learns nothing about
which document they hold, while you learn exactly that when they fetch it.

This is the pivot of the whole feature: a unique token per copy converts "someone
opened something" into "this specific copy was extracted".
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom import crypto
from phantom.config import settings
from phantom.mirror.models import CanaryToken as CanaryTokenRow

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
LABEL_MAX = 120


@dataclass(frozen=True)
class CanaryToken:
    token: str
    label: str
    url: str


def _base_url() -> str:
    return settings.mirror_base_url.rstrip("/")


def _sign(token: str) -> str:
    """Second factor on the token: a valid-looking string is not enough."""
    return crypto.hmac_hex(token, domain="canary-token")


def mint(session: Session, label: str, *, note: str = "") -> CanaryToken:
    """Create a fresh canary and return the URL to place in a document."""
    label = (label or "").strip()
    if not label:
        raise ValueError("a canary needs a label describing where it was placed")
    if len(label) > LABEL_MAX:
        raise ValueError(f"label too long (max {LABEL_MAX} characters)")

    token = secrets.token_urlsafe(16)  # 22 chars, unguessable
    session.add(
        CanaryTokenRow(
            token=token,
            signature=_sign(token),
            label=label,
            note=note,
            created_at=dt.datetime.now(dt.timezone.utc),
        )
    )
    session.commit()
    return CanaryToken(token=token, label=label, url=f"{_base_url()}/mirror/b/{token}.gif")


def verify(session: Session, token: str) -> CanaryTokenRow | None:
    """Resolve a token, rejecting anything that is malformed or unsigned.

    Every rejection reason is collapsed into ``None`` on purpose: a prober should
    not be able to tell a wrong token from a revoked one.
    """
    if not TOKEN_RE.match(token or ""):
        return None
    row = session.scalar(select(CanaryTokenRow).where(CanaryTokenRow.token == token))
    if row is None or row.revoked_at is not None:
        return None
    if not hmac.compare_digest(row.signature, _sign(token)):
        return None
    return row


def revoke(session: Session, token: str) -> bool:
    row = session.scalar(select(CanaryTokenRow).where(CanaryTokenRow.token == token))
    if row is None:
        return False
    row.revoked_at = dt.datetime.now(dt.timezone.utc)
    session.commit()
    return True


def token_fingerprint(token: str) -> str:
    """Stable short id for display, without exposing the usable token."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]

"""The single outbound-network chokepoint.

Every outbound request PHANTOM makes goes through :func:`request`. That makes
the "Who Watches the Watchers?" self-audit possible: if it did not pass through
here, it did not happen. Anything not on the allowlist raises ``EgressBlocked``.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import httpx

from phantom.config import settings

ALLOWLIST_PATH = Path(__file__).parent / "selfaudit" / "egress_allowlist.yaml"


class EgressBlocked(RuntimeError):
    """Raised when code tries to reach a host the allowlist does not cover."""


def _load_allowlist() -> list[dict]:
    import yaml

    with open(ALLOWLIST_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)["allowed"]


def _host_allowed(host: str) -> dict | None:
    host = host.lower()
    for entry in _load_allowlist():
        pattern = entry["host"].lower()
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]) or host == pattern[2:]:
                return entry
        elif host == pattern:
            return entry
    return None


def _record(url: str, purpose: str, allowed: bool) -> None:
    line = {
        "at": dt.datetime.now(dt.UTC).isoformat(),
        "url": url,
        "purpose": purpose,
        "allowed": allowed,
    }
    try:
        settings.egress_log.parent.mkdir(parents=True, exist_ok=True)
        with open(settings.egress_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
    except OSError:
        # Logging must never break the app; the in-memory audit still runs.
        pass


def request(
    method: str,
    url: str,
    *,
    purpose: str,
    headers: dict | None = None,
    params: dict | None = None,
    timeout: float = 10.0,
) -> httpx.Response:
    """Make an allowlisted outbound request and record it."""
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    entry = _host_allowed(host)
    if entry is None:
        _record(url, purpose, allowed=False)
        raise EgressBlocked(
            f"{host} is not in the PHANTOM egress allowlist. "
            "Add it to selfaudit/egress_allowlist.yaml with a justification, "
            "or do not make this call."
        )
    _record(url, purpose, allowed=True)
    return httpx.request(
        method, url, headers=headers, params=params, timeout=timeout,
        follow_redirects=False,
    )


def read_log() -> list[dict]:
    if not settings.egress_log.exists():
        return []
    out = []
    for line in settings.egress_log.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out

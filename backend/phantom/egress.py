"""The single outbound-network chokepoint.

Every outbound request PHANTOM makes goes through :func:`request`. That makes
the "Who Watches the Watchers?" self-audit possible: if it did not pass through
here, it did not happen.

The allowlist is necessary and was not sufficient. An allowlist that checks only
the hostname still permits ``http://oauth2.googleapis.com/token``, and it says
nothing about where that name actually resolves. The checks below run in order
and every one of them is a refusal, not a warning:

  scheme      https only. An OAuth exchange over cleartext is a credential on the wire.
  port        none or 443. A host is allowlisted, not every service reached through it.
  userinfo    rejected. ``https://token@host/`` is how a URL smuggles a credential
              into a log.
  literal     an IP is not a name; the allowlist is a list of names.
  resolution  every address the name resolves to must be public. This is what
              stops an allowlisted hostname from being pointed at 127.0.0.1 or
              at the operator's own network by a hostile resolver or a rebinding
              attack.

What this does not do: httpx resolves the name again when it connects, so a
resolver that answers differently between the check and the connection keeps a
narrow window open. Closing it properly means pinning the validated address
through a custom transport, which is a change worth making and is recorded as
such in docs/trust-boundaries.md rather than described here as solved.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlparse

import httpx

from phantom.config import settings
from phantom.redaction import SENSITIVE_PARAMS, safe_url

__all__ = [
    "EgressBlocked", "SENSITIVE_PARAMS", "check", "read_log",
    "request", "resolve_and_validate", "safe_url", "scrub_legacy_log",
]

ALLOWLIST_PATH = Path(__file__).parent / "selfaudit" / "egress_allowlist.yaml"

#: An allowlisted name is not a promise about how much it will send back. Without a
#: ceiling, one endpoint that streams forever is a memory exhaustion bug, and the
#: allowlist means the caller cannot even claim it was an untrusted host.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

#: The audit log is evidence, but an unbounded evidence file is a disk-filling bug.
#: At the cap it rotates to ``.1`` and keeps one generation: the oldest entries are
#: the ones dropped, and a burst big enough to rotate twice is itself the alert.
LOG_MAX_BYTES = 2 * 1024 * 1024


class EgressBlocked(RuntimeError):
    """Raised when code tries to reach something the allowlist does not cover."""


class ResponseTooLarge(EgressBlocked):
    """The endpoint answered with more than the read ceiling allows."""


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


def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_validate(host: str) -> list[str]:
    """Resolve a host and refuse if any address is not publicly routable."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise EgressBlocked(f"{host} does not resolve, so it cannot be reached") from exc
    addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise EgressBlocked(f"{host} does not resolve, so it cannot be reached")
    for address in addresses:
        if not _is_public(address):
            raise EgressBlocked(
                f"{host} resolves to {address}, which is not a public address. "
                "An allowlisted name pointed at a private, loopback or reserved "
                "destination is the shape of a rebinding attack, not a mail API."
            )
    return addresses


def _rotate_log() -> None:
    """Keep the audit log bounded. One generation, oldest entries go first."""
    try:
        if settings.egress_log.exists() and settings.egress_log.stat().st_size >= LOG_MAX_BYTES:
            settings.egress_log.replace(settings.egress_log.with_name(settings.egress_log.name + ".1"))
    except OSError:
        pass


def _record(url: str, purpose: str, allowed: bool, reason: str = "") -> None:
    line = {
        "at": dt.datetime.now(dt.UTC).isoformat(),
        # Only ever the sanitised form. See safe_url().
        "url": safe_url(url),
        "purpose": purpose,
        "allowed": allowed,
    }
    if reason:
        line["reason"] = reason
    try:
        settings.egress_log.parent.mkdir(parents=True, exist_ok=True)
        _rotate_log()
        with open(settings.egress_log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
    except OSError:
        # Logging must never break the app; the in-memory audit still runs.
        pass


def check(url: str) -> dict:
    """Validate a destination without making a request. Raises ``EgressBlocked``."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise EgressBlocked(
            f"refusing {parsed.scheme or 'a schemeless'} URL: outbound requests must use https"
        )
    if parsed.username or parsed.password:
        raise EgressBlocked("refusing a URL that carries user-info")
    if parsed.port not in (None, 443):
        raise EgressBlocked(f"refusing port {parsed.port}: allowlisted hosts are reached on 443")

    host = (parsed.hostname or "").lower()
    if not host:
        raise EgressBlocked("refusing a URL with no host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise EgressBlocked("refusing an IP literal: the allowlist is a list of names")

    entry = _host_allowed(host)
    if entry is None:
        raise EgressBlocked(
            f"{host} is not in the PHANTOM egress allowlist. "
            "Add it to selfaudit/egress_allowlist.yaml with a justification, "
            "or do not make this call."
        )
    resolve_and_validate(host)
    return entry


def request(
    method: str,
    url: str,
    *,
    purpose: str,
    headers: dict | None = None,
    params: dict | None = None,
    data: dict | None = None,
    timeout: float = 10.0,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> httpx.Response:
    """Make an allowlisted outbound request and record a sanitised entry for it."""
    try:
        check(url)
    except EgressBlocked as exc:
        _record(url, purpose, allowed=False, reason=str(exc))
        raise
    _record(url, purpose, allowed=True)
    return _streamed(
        method, url, headers=headers, params=params, data=data, timeout=timeout,
        max_bytes=max_bytes,
    )


def _streamed(
    method: str,
    url: str,
    *,
    headers: dict | None,
    params: dict | None,
    data: dict | None,
    timeout: float,
    max_bytes: int,
) -> httpx.Response:
    """Read at most `max_bytes`, then refuse. The body is never fully buffered blind."""
    chunks: list[bytes] = []
    size = 0
    with httpx.stream(
        method, url, headers=headers, params=params, data=data, timeout=timeout,
        follow_redirects=False, verify=True,
    ) as response:
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > max_bytes:
                _record(url, "response.too_large", allowed=False, reason=f"more than {max_bytes} bytes")
                raise ResponseTooLarge(f"{url} sent more than {max_bytes} bytes; read stopped")
            chunks.append(chunk)
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=b"".join(chunks),
            request=response.request,
        )


def read_log() -> list[dict]:
    if not settings.egress_log.exists():
        return []
    out = []
    for line in settings.egress_log.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def scrub_legacy_log() -> int:
    """Rewrite entries written before values were dropped. Returns lines changed.

    The old format stored the complete URL, which meant an OAuth revocation
    token sat in a plain file. Those lines still exist on any install that ran
    the earlier version, so they are rewritten in place rather than left for
    someone to find.
    """
    if not settings.egress_log.exists():
        return 0
    changed = 0
    rebuilt = []
    for line in settings.egress_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            changed += 1
            continue
        url = row.get("url", "")
        clean = safe_url(url)
        if clean != url:
            row["url"] = clean
            changed += 1
        rebuilt.append(json.dumps(row))
    if changed:
        settings.egress_log.write_text("\n".join(rebuilt) + "\n", encoding="utf-8")
    return changed

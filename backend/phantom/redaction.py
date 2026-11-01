"""One implementation of "do not keep this".

Every place PHANTOM decides not to retain something calls in here, so the rule
is stated once rather than re-derived per module. The principle is that a URL
and its parameters are not neutral: a tracking link routinely carries a
recipient-specific identifier or a signed token, and keeping it "for analysis"
turns an observation about infrastructure into a record about a person.

What survives: the host, the path, the fact that parameters existed, and their
names. What does not: any parameter value, and any IP literal.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

WITHHELD = "<withheld>"
IP_WITHHELD = "<ip-withheld>"

#: Query parameter names that are structurally credentials. They are dropped
#: from egress logs entirely.
SENSITIVE_PARAMS = frozenset(
    {
        "token", "access_token", "refresh_token", "id_token", "code", "secret",
        "client_secret", "password", "passwd", "api_key", "apikey", "key",
        "sig", "signature", "auth", "authorization", "credential",
    }
)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_CANDIDATE = re.compile(r"[0-9a-fA-F]{2,4}(?::[0-9a-fA-F]{0,4}){2,7}")


def safe_url(url: str) -> str:
    """A URL with every query value removed, for logging and for evidence.

    Not redaction: redaction keeps the shape and hopes the pattern matched the
    secret. This drops the values and keeps only their names, so a credential
    cannot be stored by being spelled in a way nobody predicted.
    """
    parsed = urlparse(url or "")
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else (url or "")
    if parsed.query:
        names = sorted({pair.split("=", 1)[0] for pair in parsed.query.split("&") if pair})
        base = f"{base}?{'&'.join(n + '=' + WITHHELD for n in names)}"
    return base


def redact_params(params: dict | None) -> dict:
    """Keep the names, drop the values. Shape stays a dict of strings."""
    return {str(name): WITHHELD for name in (params or {})}


def _is_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def redact_ips(value):
    """Recursively replace IP literals with a marker, keeping the structure.

    An address is a weak identifier and a personal one. The analysis needs the
    hop count and the hostnames, not the addresses, so the addresses go.
    """
    if isinstance(value, str):
        text = _IPV4.sub(IP_WITHHELD, value)
        return _IPV6_CANDIDATE.sub(
            lambda m: IP_WITHHELD if _is_ip(m.group(0)) else m.group(0), text
        )
    if isinstance(value, list):
        return [redact_ips(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_ips(item) for item in value)
    if isinstance(value, dict):
        return {key: redact_ips(item) for key, item in value.items()}
    return value

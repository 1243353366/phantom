"""Gmail ingestion.

Two tiers, because the honest answer differs from the convenient one:

  metadata tier (default)  ``gmail.metadata``
      Headers, labels, authentication results. Enough for sender infrastructure,
      relay chains and DKIM identity. Not enough for tracking pixels, because
      pixels live in the body.

  body tier (explicit opt-in)  ``gmail.readonly``
      Adds HTML so pixels and redirect wrappers become visible. The body is
      parsed in memory and then discarded: what survives is a URL, a reason and
      a hash. Granting this scope gives the application more than it needs in
      principle, which is exactly why it is off by default and stated plainly in
      the consent text.

PHANTOM never requests ``gmail.send`` or ``gmail.modify``. It cannot send, label
or delete your mail.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode

from phantom import egress
from phantom.collector.headers import ParsedEmail, parse_eml

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - an endpoint, not a secret
API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"

METADATA_SCOPE = "https://www.googleapis.com/auth/gmail.metadata"
BODY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

# Headers we ask for by name in the metadata tier.
WANTED_HEADERS = [
    "From", "Reply-To", "Return-Path", "Date", "Message-ID", "Subject",
    "Received", "DKIM-Signature", "Authentication-Results", "List-Unsubscribe",
    "X-Mailer", "Content-Type",
]


@dataclass
class GmailSession:
    access_token: str
    refresh_token: str | None = None
    scope: str = ""
    tier: str = "metadata"


def authorization_url(*, client_id: str, redirect_uri: str, state: str,
                      body_tier: bool = False) -> str:
    """Build the consent URL. Read-only, no send, no modify."""
    scopes = [METADATA_SCOPE] if not body_tier else [BODY_SCOPE]
    scopes += ["openid", "email"]
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "access_type": "offline",
        "include_granted_scopes": "false",
        "prompt": "consent",
        "state": state,
    }
    return f"{AUTH_URL}?{urlencode(params)}"


def exchange_code(*, client_id: str, client_secret: str, code: str,
                  redirect_uri: str) -> GmailSession:
    """Swap the authorization code for tokens, then drop the code."""

    allowlisted = _assert_allowlisted(TOKEN_URL)
    if not allowlisted:  # pragma: no cover - defensive
        raise egress.EgressBlocked("token endpoint missing from allowlist")
    response = egress.request(
        "POST",
        TOKEN_URL,
        purpose="exchange Gmail authorization code for tokens",
        params={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
    )
    if response.status_code >= 400:
        raise RuntimeError(f"token exchange failed: HTTP {response.status_code}")
    data = response.json()
    granted = data.get("scope", "")
    return GmailSession(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token"),
        scope=granted,
        tier="body" if BODY_SCOPE in granted else "metadata",
    )


def _assert_allowlisted(url: str) -> bool:
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    return egress._host_allowed(host) is not None


def revoke(access_token: str) -> None:
    """Hand the token back. Revocation is a first-class operation, not a docs page.

    The token travels in the request body, not the query string. A query string
    is part of the URL, and a URL is the one thing that reliably ends up in
    logs, proxies, browser history and crash reports.
    """
    egress.request(
        "POST",
        "https://oauth2.googleapis.com/revoke",
        purpose="revoke Gmail access when the user asks",
        data={"token": access_token},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )


def list_message_ids(session: GmailSession, *, query: str = "newer_than:30d",
                     limit: int = 50) -> list[str]:
    response = egress.request(
        "GET", f"{API_BASE}/messages",
        purpose="list message ids for the authorized mailbox",
        headers={"Authorization": f"Bearer {session.access_token}"},
        params={"q": query, "maxResults": min(limit, 500)},
    )
    return [m["id"] for m in response.json().get("messages", [])]


def fetch_message(session: GmailSession, message_id: str) -> dict:
    """Metadata tier by default. Body tier only when explicitly granted."""
    if session.tier == "body":
        fmt = "full"
    else:
        fmt = "metadata"
    response = egress.request(
        "GET", f"{API_BASE}/messages/{message_id}",
        purpose=f"read message {fmt} (tier={session.tier})",
        headers={"Authorization": f"Bearer {session.access_token}"},
        params={"format": fmt, **({"metadataHeaders": WANTED_HEADERS} if fmt == "metadata" else {})},
    )
    return response.json()


def to_parsed(message: dict) -> ParsedEmail:
    """Turn an API payload into the same structure a local .eml produces."""
    payload = message.get("payload", {})
    headers = {h["name"]: h["value"] for h in payload.get("headers", [])}

    lines = []
    for name, value in headers.items():
        # Received and DKIM-Signature legitimately repeat.
        lines.append(f"{name}: {value}")
    raw = "\n".join(lines) + "\n\n"

    html = _find_html(payload) if message.get("_tier") == "body" else ""
    if html is None:
        html = ""
    return parse_eml(raw, html_body=html)


def _find_html(part: dict) -> str | None:
    """Depth-first hunt for the HTML alternative, then forget the body."""
    import base64

    if part.get("mimeType") == "text/html":
        data = part.get("body", {}).get("data")
        if data:
            try:
                return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode(
                    "utf-8", "ignore"
                )
            except Exception:
                return None
    for child in part.get("parts", []) or []:
        found = _find_html(child)
        if found:
            return found
    return None


def collect(session: GmailSession, *, query: str = "newer_than:30d",
            limit: int = 50) -> list[ParsedEmail]:
    out = []
    for msg_id in list_message_ids(session, query=query, limit=limit):
        raw = fetch_message(session, msg_id)
        raw["_tier"] = session.tier
        out.append(to_parsed(raw))
    return out

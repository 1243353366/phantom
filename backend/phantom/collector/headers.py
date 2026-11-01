"""Metadata-first email parsing.

Only headers, URLs and structural HTML signals are read. Bodies are not
retained, hashed into storage, or sent anywhere. This is the architectural
promise in docs/privacy-model.md, enforced here rather than described in a
README.
"""
from __future__ import annotations

import datetime as dt
import email
import re
from dataclasses import dataclass, field
from email.utils import parseaddr, parsedate_to_datetime

from phantom.collector.pixels import LinkObservation, PixelObservation, find_links, find_pixels

RECEIVED_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
RECEIVED_BY = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
DKIM_D = re.compile(r"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)
DKIM_S = re.compile(r"\bs\s*=\s*([^;\s]+)", re.IGNORECASE)
AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)


def _bare_domain(value: str) -> str:
    value = (value or "").strip().strip("<>").lower().strip(".")
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    return value


@dataclass
class ParsedEmail:
    message_id: str
    sent_at: dt.datetime | None
    from_address: str
    from_domain: str
    display_name: str = ""
    subject_hash: str = ""
    reply_to_domains: list[str] = field(default_factory=list)
    return_path_domain: str | None = None
    dkim: list[dict] = field(default_factory=list)
    auth_results: list[dict] = field(default_factory=list)
    received_hops: list[dict] = field(default_factory=list)
    pixels: list[PixelObservation] = field(default_factory=list)
    links: list[LinkObservation] = field(default_factory=list)
    mailer: str | None = None

    # --- derived -----------------------------------------------------
    @property
    def redirect_targets(self) -> list[str]:
        return sorted({l.target_host for l in self.links if l.target_host})

    @property
    def redirector_hosts(self) -> list[str]:
        return sorted({l.host for l in self.links if l.is_redirector})

    @property
    def pixel_hosts(self) -> list[str]:
        return sorted({p.host for p in self.pixels})

    @property
    def relay_hosts(self) -> list[str]:
        hosts: list[str] = []
        for hop in self.received_hops:
            for key in ("from_host", "by_host"):
                h = hop.get(key)
                if h and h not in hosts:
                    hosts.append(h)
        return hosts

    def subjects(self) -> list[str]:
        """Node keys this message touches, deduplicated and ordered."""
        out = [f"org:domain:{self.from_domain}"] if self.from_domain else []
        for h in self.pixel_hosts:
            out.append(f"domain:{h}")
        for h in self.redirector_hosts:
            out.append(f"domain:{h}")
        for h in self.redirect_targets:
            out.append(f"domain:{h}")
        for d in self.reply_to_domains:
            out.append(f"domain:{d}")
        return list(dict.fromkeys(out))


def parse_headers(msg: email.message.Message) -> dict:
    received = msg.get_all("Received") or []
    hops = []
    for raw in received:
        from_m = RECEIVED_FROM.search(raw)
        by_m = RECEIVED_BY.search(raw)
        ip_m = IP_RE.search(raw)
        hops.append(
            {
                "from_host": _bare_domain(from_m.group(1)) if from_m else None,
                "by_host": _bare_domain(by_m.group(1)) if by_m else None,
                "ip": ip_m.group(1) if ip_m else None,
            }
        )

    dkim = []
    for raw in msg.get_all("DKIM-Signature") or []:
        d = DKIM_D.search(raw)
        s = DKIM_S.search(raw)
        if d:
            dkim.append({"domain": _bare_domain(d.group(1)), "selector": s.group(1) if s else None})

    auth = []
    for raw in msg.get_all("Authentication-Results") or []:
        for mechanism, result in AUTH_RESULT.findall(raw):
            auth.append({"mechanism": mechanism.lower(), "result": result.lower()})

    return {"received_hops": hops, "dkim": dkim, "auth_results": auth}


def parse_eml(raw: bytes | str, *, html_body: str | None = None) -> ParsedEmail:
    """Parse a raw RFC822 message into provenance-ready observations."""
    msg = email.message_from_bytes(raw) if isinstance(raw, (bytes, bytearray)) else email.message_from_string(raw)

    display, addr = parseaddr(msg.get("From", ""))
    from_domain = _bare_domain(addr)

    sent_at = None
    if msg.get("Date"):
        try:
            sent_at = parsedate_to_datetime(msg["Date"])
            if sent_at.tzinfo is None:
                sent_at = sent_at.replace(tzinfo=dt.timezone.utc)
        except (TypeError, ValueError):
            sent_at = None

    reply_to = [
        _bare_domain(parseaddr(v)[1]) for v in (msg.get_all("Reply-To") or []) if parseaddr(v)[1]
    ]

    html = html_body if html_body is not None else _html_part(msg)

    return ParsedEmail(
        message_id=(msg.get("Message-ID") or "").strip() or "missing-message-id",
        sent_at=sent_at,
        from_address=addr.lower(),
        from_domain=from_domain,
        display_name=display,
        reply_to_domains=[d for d in reply_to if d],
        return_path_domain=_bare_domain(msg.get("Return-Path", "")) or None,
        mailer=(msg.get("X-Mailer") or None),
        pixels=find_pixels(html),
        links=find_links(html),
        **parse_headers(msg),
    )


def _html_part(msg: email.message.Message) -> str:
    """Extract the HTML alternative if present, without touching plain bodies."""
    if not msg.is_multipart():
        if msg.get_content_type() == "text/html":
            payload = msg.get_payload(decode=True) or b""
            return payload.decode(msg.get_content_charset() or "utf-8", "ignore")
        return ""
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True) or b""
            return payload.decode(part.get_content_charset() or "utf-8", "ignore")
    return ""

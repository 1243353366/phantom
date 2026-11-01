"""What a plain HTTP request volunteers about itself.

Deliberately narrow. Everything here comes from headers the client chose to send.
There is no JavaScript challenge, no canvas trick, no TLS-fingerprint harvesting,
because those cross from "observing what was offered" into interrogating the
visitor, and PHANTOM does not interrogate.

The output has two jobs:

1. Group repeat visitors (``origin_hmac``, ``client_hash``).
2. Decide whether this looks like a collector or a person (``extraction_signals``).
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from phantom import crypto
from phantom.config import settings

# Headers we keep. Anything else in the request is dropped unread.
KEPT_HEADERS = (
    "user-agent", "accept", "accept-language", "accept-encoding",
    "referer", "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile",
    "connection", "range", "if-none-match",
)

SCRIPTED_UA = re.compile(
    r"(curl|wget|python-requests|python-urllib|aiohttp|httpx|scrapy|go-http-client|"
    r"java/|okhttp|axios|node-fetch|libwww-perl|headlesschrome|phantomjs|"
    r"puppeteer|playwright|selenium|bot|spider|crawler|scraper)",
    re.IGNORECASE,
)

#: Named collection tools. Grouping by tool rather than by exact version means a
#: scraper that upgrades itself stays the same cluster, while two different tools
#: stay distinct instead of collapsing into one "scripted" blob.
TOOL_PATTERNS = [
    ("python-requests", re.compile(r"python-requests", re.I)),
    ("scrapy", re.compile(r"scrapy", re.I)),
    ("curl", re.compile(r"\bcurl/", re.I)),
    ("wget", re.compile(r"\bwget/", re.I)),
    ("httpx", re.compile(r"\bhttpx/", re.I)),
    ("aiohttp", re.compile(r"aiohttp", re.I)),
    ("go-http-client", re.compile(r"go-http-client", re.I)),
    ("okhttp", re.compile(r"okhttp", re.I)),
    ("java", re.compile(r"\bjava/", re.I)),
    ("node-fetch", re.compile(r"node-fetch", re.I)),
    ("axios", re.compile(r"\baxios/", re.I)),
    ("libwww-perl", re.compile(r"libwww-perl", re.I)),
    ("playwright", re.compile(r"playwright", re.I)),
    ("selenium", re.compile(r"selenium", re.I)),
    ("puppeteer", re.compile(r"puppeteer", re.I)),
    ("headless-chromium", re.compile(r"headlesschrome", re.I)),
]

_CLIENT_FAMILY = [
    ("scripted", SCRIPTED_UA),
    ("headless", re.compile(r"headless", re.I)),
    ("browser-chromium", re.compile(r"Chrome/\d+")),
    ("browser-firefox", re.compile(r"Firefox/\d+")),
    ("browser-safari", re.compile(r"Version/\d+.*Safari/")),
    ("mail-proxy", re.compile(r"(GoogleImageProxy|Yahoo|Outlook|Mail)", re.I)),
]


@dataclass
class AttemptFingerprint:
    origin_hmac: str
    origin_raw: str | None
    asn: int | None
    asn_org: str | None
    client_family: str
    client_tool: str
    client_hash: str
    headers: dict[str, str] = field(default_factory=dict)
    extraction_signals: list[dict] = field(default_factory=list)

    @property
    def looks_automated(self) -> bool:
        return any(s["weight"] >= 2 for s in self.extraction_signals)


def _client_tool(ua: str) -> str:
    for name, pattern in TOOL_PATTERNS:
        if pattern.search(ua):
            return name
    return ""


def _client_family(ua: str) -> str:
    if not ua:
        return "no-user-agent"
    for name, pattern in _CLIENT_FAMILY:
        if pattern.search(ua):
            return name
    return "other"


def _load_asn_table(path: Path) -> list[tuple[ipaddress._BaseNetwork, int, str]]:
    if not path.exists():
        return []
    table = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) < 2:
                continue
            try:
                net = ipaddress.ip_network(row[0].strip(), strict=False)
                asn = int(row[1])
            except ValueError:
                continue
            table.append((net, asn, row[2].strip() if len(row) > 2 else ""))
    return table


def _lookup_asn(ip: str, table_path: Path | None = None) -> tuple[int | None, str | None]:
    """Local table only. No network call, by design.

    Handing your canary hits to an IP-intelligence provider would leak the exact
    information the canary exists to keep.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    for net, asn, org in _load_asn_table(table_path or settings.asn_db):
        if net.version == address.version and address in net:
            return asn, org
    return None, None


def fingerprint(
    *,
    source_ip: str,
    headers: dict[str, str],
    method: str = "GET",
    path: str = "",
    asn_db: Path | None = None,
) -> AttemptFingerprint:
    lowered = {k.lower(): (v or "") for k, v in headers.items()}
    kept = {k: lowered[k] for k in KEPT_HEADERS if lowered.get(k)}

    ua = kept.get("user-agent", "")
    client_family = _client_family(ua)
    client_tool = _client_tool(ua)
    # Group by what the client actually is, not by the exact version string, so
    # one scraper upgrading itself does not become a new campaign.
    client_hash = crypto.hmac_hex(
        "|".join(
            [
                client_family,
                client_tool,
                kept.get("sec-ch-ua", ""),
                kept.get("sec-ch-ua-platform", ""),
            ]
        ),
        domain="mirror-client",
    )

    signals: list[dict] = []

    def flag(name: str, weight: int, detail: str) -> None:
        signals.append({"signal": name, "weight": weight, "detail": detail})

    if SCRIPTED_UA.search(ua):
        flag("scripted_user_agent", 3, f"user agent names a non-browser client: {ua[:80]}")
    if client_family == "no-user-agent":
        flag("missing_user_agent", 3, "no User-Agent header at all")
    if not kept.get("accept-language"):
        flag("no_accept_language", 2, "a browser normally sends Accept-Language")
    if not kept.get("accept"):
        flag("no_accept_header", 1, "no Accept header")
    if not kept.get("referer"):
        flag("no_referer", 1, "fetched directly rather than from page context")
    if method.upper() not in ("GET", "HEAD"):
        flag("unusual_method", 2, f"request method {method}")
    if client_family == "headless":
        flag("headless_browser", 3, "headless browser stack")
    if re.search(r"(chrome/\d+).*(chrome/\d+)", ua, re.I) and client_family == "scripted":
        flag("inconsistent_ua", 1, "user agent mixes client identities")

    asn, asn_org = _lookup_asn(source_ip, asn_db)

    return AttemptFingerprint(
        origin_hmac=crypto.hmac_hex(source_ip, domain="mirror-origin"),
        origin_raw=source_ip if settings.retain_raw_ip else None,
        asn=asn,
        asn_org=asn_org,
        client_family=client_family,
        client_tool=client_tool,
        client_hash=client_hash,
        headers=kept,
        extraction_signals=signals,
    )

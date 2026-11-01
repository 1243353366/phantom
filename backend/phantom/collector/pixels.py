"""Detection of tracking pixels and redirect infrastructure in message HTML.

Heuristics are intentionally explainable. Every hit carries the reason it was
flagged so the UI can show it instead of asking for trust.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, unquote, urlparse

from phantom.registry.tracker_registry import registry

INVISIBLE_STYLES = ("display:none", "visibility:hidden", "opacity:0", "height:1px", "width:1px")
SUSPICIOUS_PATH = re.compile(
    r"(/open|/o/|/track|/pixel|/beacon|/wf/open|/e/o/|/t/c|/impression|/collect|/i\.gif)",
    re.IGNORECASE,
)
SUSPICIOUS_FILENAME = re.compile(r"(^|[^a-z])(spacer|blank|pixel|1x1|clear|transparent)\.(gif|png)", re.IGNORECASE)
REDIRECT_PARAMS = ("url", "u", "redirect", "target", "r", "link", "to", "dest", "destination")


@dataclass
class PixelObservation:
    url: str
    host: str
    reasons: list[str] = field(default_factory=list)
    width: str | None = None
    height: str | None = None
    params: dict[str, str] = field(default_factory=dict)

    @property
    def confidence(self) -> float:
        """Three independent reasons is strong evidence, one is suggestive."""
        return min(0.4 + 0.2 * len(self.reasons), 0.95)

    @property
    def is_tracking_pixel(self) -> bool:
        return bool(self.reasons)


@dataclass
class LinkObservation:
    url: str
    host: str
    is_redirector: bool = False
    target_host: str | None = None
    reasons: list[str] = field(default_factory=list)
    params: dict[str, str] = field(default_factory=dict)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.images: list[dict] = []
        self.anchors: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "img" and a.get("src"):
            self.images.append(a)
        elif tag.lower() == "a" and a.get("href"):
            self.anchors.append(a)

    handle_startendtag = handle_starttag


def _flat_params(query: dict[str, list[str]]) -> dict[str, str]:
    return {k: (v[0] if v else "") for k, v in query.items()}


def find_pixels(html: str) -> list[PixelObservation]:
    """Return every image that looks like a tracking beacon, worst offenders first."""
    if not html:
        return []
    parser = _Extractor()
    try:
        parser.feed(html)
    except Exception:  # malformed HTML must not abort collection
        pass

    out: list[PixelObservation] = []
    for attrs in parser.images:
        src = attrs.get("src", "").strip()
        if not src.lower().startswith(("http://", "https://")):
            continue
        parsed = urlparse(src)
        host = (parsed.hostname or "").lower()
        query = parse_qs(parsed.query, keep_blank_values=True)
        reasons: list[str] = []

        w = attrs.get("width", "").strip().lower().rstrip("px")
        h = attrs.get("height", "").strip().lower().rstrip("px")
        if (w in ("0", "1") and h in ("0", "1")) and (w or h):
            reasons.append(f"explicit size {w or '?'}x{h or '?'}")
        style = attrs.get("style", "").replace(" ", "").lower()
        for s in INVISIBLE_STYLES:
            if s in style:
                reasons.append(f"invisible style ({s})")
                break
        if attrs.get("hidden") or attrs.get("aria-hidden") == "true":
            reasons.append("hidden attribute")
        if SUSPICIOUS_PATH.search(parsed.path or ""):
            reasons.append(f"beacon-shaped path {parsed.path}")
        if SUSPICIOUS_FILENAME.search(parsed.path.rsplit("/", 1)[-1] if parsed.path else ""):
            reasons.append("placeholder image name")
        if registry.classify_identifier_params(query):
            reasons.append("carries a known identifier parameter")

        obs = PixelObservation(
            url=src, host=host, reasons=reasons,
            width=w or None, height=h or None,
            params=_flat_params(query),
        )
        if obs.is_tracking_pixel:
            out.append(obs)

    out.sort(key=lambda o: o.confidence, reverse=True)
    return out


def _decode_target(raw: str) -> str | None:
    """Redirect params hide their destination in one of three usual ways."""
    candidates = [unquote(raw)]
    try:
        padded = raw + "=" * (-len(raw) % 4)
        candidates.append(base64.urlsafe_b64decode(padded).decode("utf-8", "ignore"))
    except (binascii.Error, ValueError):
        pass
    if re.fullmatch(r"[0-9a-fA-F]+", raw or "") and len(raw) % 2 == 0:
        try:
            candidates.append(bytes.fromhex(raw).decode("utf-8", "ignore"))
        except ValueError:
            pass
    for cand in candidates:
        if cand.startswith(("http://", "https://")):
            return cand
    return None


def find_links(html: str) -> list[LinkObservation]:
    """Find links, resolving click-tracking redirectors to their real host."""
    if not html:
        return []
    parser = _Extractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    out: list[LinkObservation] = []
    for attrs in parser.anchors:
        href = attrs.get("href", "").strip()
        if not href.lower().startswith(("http://", "https://")):
            continue
        parsed = urlparse(href)
        host = (parsed.hostname or "").lower()
        query = parse_qs(parsed.query, keep_blank_values=True)
        reasons: list[str] = []
        target_host = None

        for p in REDIRECT_PARAMS:
            if p in query and query[p]:
                decoded = _decode_target(query[p][0])
                if decoded:
                    target_host = (urlparse(decoded).hostname or "").lower()
                    reasons.append(f"wraps destination in '{p}=' parameter")
                    break
        entry = registry.resolve(host)
        if entry and entry.category in ("esp", "redirect") and target_host:
            reasons.append(f"known {entry.category} click-tracking host ({entry.name})")
        if SUSPICIOUS_PATH.search(parsed.path or "") and target_host:
            reasons.append(f"redirector path {parsed.path}")

        out.append(
            LinkObservation(
                url=href, host=host,
                is_redirector=bool(target_host),
                target_host=target_host,
                reasons=reasons,
                params=_flat_params(query),
            )
        )
    return out

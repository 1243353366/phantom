"""robots.txt and noindex are different directives, and conflating them is the bug.

``robots.txt`` is crawler guidance: it asks a compliant crawler not to *fetch* a
path. ``noindex`` is an indexing directive: it asks a search engine not to
*include* the URL in results.

The consequence is a trap. ``Disallow: /`` on a URL does not remove it from
search results, and worse, it prevents the crawler from ever fetching the page,
so the ``noindex`` that would have removed it is never read. A page can sit in an
index for years behind a full disallow. The fix is the opposite of the intuition:
allow the crawl, serve ``noindex``, then optionally disallow once it is gone.

This module answers three questions separately and refuses to collapse them into
one "is it private" verdict. Parsing follows RFC 9309: longest match wins, and
allow wins a tie.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

# ---------------------------------------------------------------- robots.txt

_RULE = re.compile(r"^(allow|disallow)\s*:\s*(.*)$", re.IGNORECASE)
_AGENT = re.compile(r"^user-agent\s*:\s*(.*)$", re.IGNORECASE)


@dataclass
class Group:
    agents: list[str] = field(default_factory=list)
    rules: list[tuple[bool, str]] = field(default_factory=list)


def parse_robots(text: str) -> list[Group]:
    """Group rules per RFC 9309, tolerating comments and stray whitespace."""
    groups: list[Group] = []
    current = Group()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            # A blank line ends a group, but only if it has rules already.
            if current.rules:
                groups.append(current)
                current = Group()
            continue

        agent = _AGENT.match(line)
        if agent:
            if current.rules:
                groups.append(current)
                current = Group()
            current.agents.append(agent.group(1).strip().lower())
            continue

        rule = _RULE.match(line)
        if rule and current.agents:
            pattern = rule.group(2).strip()
            # "Disallow:" with nothing after it means no restriction at all.
            if pattern or rule.group(1).lower() == "allow":
                current.rules.append((rule.group(1).lower() == "allow", pattern))

    if current.rules or current.agents:
        groups.append(current)
    return groups


def _pattern_to_regex(pattern: str) -> re.Pattern:
    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    escaped = re.escape(body).replace(r"\*", ".*")
    return re.compile(f"^{escaped}{'$' if anchored else ''}")


def is_allowed(robots_text: str, path: str, *, agent: str = "*") -> tuple[bool, str]:
    """Whether this agent may fetch this path, and which rule decided."""
    target = path or "/"
    asked = agent.strip().lower()
    groups = parse_robots(robots_text)

    named = [g for g in groups if asked in g.agents]
    chosen = named or [g for g in groups if "*" in g.agents]
    if not chosen:
        return True, "no matching user-agent group: nothing is disallowed"

    matches: list[tuple[int, bool, str]] = []
    for group in chosen:
        for allow, pattern in group.rules:
            if not pattern:
                continue
            if _pattern_to_regex(pattern).match(target):
                matches.append((len(pattern), allow, pattern))

    if not matches:
        return True, "no rule matched this path"

    longest = max(length for length, _, _ in matches)
    finalists = [(allow, pattern) for length, allow, pattern in matches if length == longest]
    allowed = any(allow for allow, _ in finalists)
    pattern = finalists[0][1]
    verdict = "Allow" if allowed else "Disallow"
    return allowed, f"{verdict}: {pattern}"


# ------------------------------------------------------------------ noindex

_META = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_ATTR = re.compile(r"""(\w[\w:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)


def directives_from_html(html: str) -> list[str]:
    """Robots directives declared by meta tags, lowercased and split."""
    found: list[str] = []
    for tag in _META.findall(html or ""):
        attrs = {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "") for m in _ATTR.finditer(tag)}
        name = attrs.get("name", "").lower()
        if name in {"robots", "googlebot", "bingbot"}:
            found.extend(part.strip().lower() for part in attrs.get("content", "").split(",") if part.strip())
    return found


def directives_from_header(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip().lower() for part in value.split(",") if part.strip()]


def declares_noindex(directives: list[str]) -> bool:
    """``none`` is shorthand for noindex, nofollow."""
    return any(d in {"noindex", "none"} or d.startswith("noindex") for d in directives)


# ----------------------------------------------------------------- verdict

INDEXABLE = "yes"
NOT_INDEXABLE = "no"
UNVERIFIABLE = "unverifiable"


@dataclass
class Finding:
    url: str
    crawl_allowed: bool
    crawl_reason: str
    robots_status: int | None
    noindex_declared: bool
    directives: list[str]
    indexable: str
    reason: str
    caveat: str | None = None


def verdict(
    *,
    url: str,
    robots_text: str | None,
    robots_status: int | None,
    html: str | None = None,
    x_robots_tag: str | None = None,
    path: str = "/",
) -> Finding:
    """Answer the two questions separately, then say what follows from both."""
    if robots_status is not None and robots_status >= 500:
        # RFC 9309: an unreachable robots.txt is treated as a full disallow.
        allowed, crawl_reason = False, f"robots.txt returned {robots_status}: treated as disallow-all"
    elif robots_status in {401, 403}:
        allowed, crawl_reason = False, f"robots.txt returned {robots_status}: treated as disallow-all"
    elif robots_text is None:
        allowed, crawl_reason = True, "no robots.txt: crawling is unrestricted"
    else:
        allowed, crawl_reason = is_allowed(robots_text, path)

    directives = directives_from_header(x_robots_tag) + directives_from_html(html or "")
    noindex = declares_noindex(directives)

    if not allowed:
        # The trap this module exists for.
        outcome = UNVERIFIABLE
        reason = (
            "Crawling is disallowed, so a crawler never fetches the page and can "
            "never read a noindex directive on it. The URL can still appear in "
            "results when other pages link to it. robots.txt is crawler guidance, "
            "not an indexing directive: it will not remove this URL from an index."
        )
        caveat = (
            "To exclude a page: allow the crawl, serve noindex until the engine "
            "drops it, and only then disallow. Confirm in the search engine's own "
            "URL inspector, which is the only authority on what it has indexed."
        )
    elif noindex:
        outcome = NOT_INDEXABLE
        reason = (
            "Crawling is allowed and the page declares noindex, so a compliant "
            "engine may fetch it and must not keep it in results."
        )
        caveat = (
            "Removal happens on recrawl, which can take weeks. Until then the URL "
            "can still appear."
        )
    else:
        outcome = INDEXABLE
        reason = (
            "Crawling is allowed and no noindex directive was found, so nothing "
            "asks an engine to keep this URL out of results."
        )
        caveat = None

    return Finding(
        url=url,
        crawl_allowed=allowed,
        crawl_reason=crawl_reason,
        robots_status=robots_status,
        noindex_declared=noindex,
        directives=directives,
        indexable=outcome,
        reason=reason,
        caveat=caveat,
    )


def as_dict(finding: Finding) -> dict:
    return asdict(finding)

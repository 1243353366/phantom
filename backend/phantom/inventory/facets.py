"""What an own-account inventory is allowed to contain.

The point of this package is what it refuses. A platform export is a bundle of
files about the whole network, and only a handful of fields in it describe the
operator. Everything else describes other people, so the adapter reads a named
allowlist of keys and an explicit deny list wins over it.

A deny list that can be overridden by an allow is not a deny list, so the check
order is: denied key or denied filename, then allowed key, then ignored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Export keys that describe the operator, mapped to the facet they yield.
#: ``global_name`` is deliberately absent: it is a free-text display name the
#: operator chose, not an identifier, and parsing it would invite name matching.
ALLOWED_KEYS: dict[str, str] = {
    "username": "handle",
    "user_name": "handle",
    "handle": "handle",
    "email": "email",
    "emails": "email",
    "email_address": "email",
    "email_addresses": "email",
    "phone": "phone",
    "phone_number": "phone",
    "phone_numbers": "phone",
    "id": "account_id",
    "user_id": "account_id",
}

#: Substrings that mark a key or filename as describing other people, or as
#: carrying content rather than identity. Matched case-insensitively.
DENIED_MARKERS: tuple[str, ...] = (
    "message", "messages", "dm", "dms", "friend", "friends", "relationship",
    "relationships", "member", "members", "recipient", "recipients", "activity",
    "analytics", "connections", "following", "followers", "blocked", "server",
    "servers", "guild", "guilds", "channel", "channels", "thread", "threads",
    "attachment", "attachments", "reaction", "reactions", "login", "logins",
    "session", "sessions", "ip", "address", "avatar", "payment", "billing",
)

_SEPARATORS = re.compile(r"[\s_\-]+")

#: Punctuation a phone number can carry without changing which number it is.
_PHONE_PUNCTUATION = re.compile(r"[\s()\-./\u2010-\u2015]")


def normalise_phone(value: str) -> str:
    """Strip punctuation and keep the leading ``+`` and every digit.

    A country code is never added or removed. ``+15550100`` and ``5550100`` stay
    distinct, because deciding they are the same number would be an inference
    about who owns it rather than an observation of a shared value. The cost is
    real: the same number written nationally on one platform and internationally
    on another will not join, and the report says so rather than guessing.
    """
    squeezed = _PHONE_PUNCTUATION.sub("", (value or "").strip())
    return squeezed if squeezed.startswith("+") else squeezed


@dataclass(frozen=True)
class Facet:
    """One identifier belonging to the operator's own account."""

    kind: str
    value: str
    source_field: str

    @property
    def normalised(self) -> str:
        """The value used for matching, so two spellings of one identifier agree.

        Email is lowercased and trimmed; a handle additionally has separators
        removed; a phone loses punctuation only. All three are the same operation
        on every platform, which is what makes a cross-platform join mean
        something: it is equality of a digest, not a similarity score.
        """
        value = self.value.strip().lower()
        if self.kind == "handle":
            return _SEPARATORS.sub("", value)
        if self.kind == "phone":
            return normalise_phone(value)
        return value


@dataclass
class Refusal:
    """Something present in the export that was not read, and why."""

    item: str
    reason: str


@dataclass
class Reading:
    """The result of looking at an export before storing anything."""

    platform: str
    facets: list[Facet] = field(default_factory=list)
    files_read: list[str] = field(default_factory=list)
    refusals: list[Refusal] = field(default_factory=list)

    def refused_for(self, marker: str) -> list[Refusal]:
        return [r for r in self.refusals if marker in r.reason]


def is_denied(name: str) -> str | None:
    """Return the marker that disqualifies this key or filename, if any."""
    lowered = (name or "").lower()
    for marker in DENIED_MARKERS:
        if marker in lowered:
            return marker
    return None


def facet_kind(key: str) -> str | None:
    """The facet a key yields, or None when it must not be read."""
    if is_denied(key):
        return None
    return ALLOWED_KEYS.get((key or "").lower())


def extract_keys(obj: dict, *, where: str) -> tuple[list[Facet], list[Refusal]]:
    """Pull allowed facets out of one mapping, recording what was refused."""
    facets: list[Facet] = []
    refusals: list[Refusal] = []
    for key, value in (obj or {}).items():
        denied = is_denied(str(key))
        if denied is not None:
            refusals.append(
                Refusal(
                    item=f"{where}:{key}",
                    reason=f"describes other people or content ('{denied}')",
                )
            )
            continue
        kind = facet_kind(str(key))
        if kind is None:
            continue
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            continue
        text = str(value).strip()
        if text:
            facets.append(Facet(kind=kind, value=text, source_field=str(key)))
    return facets, refusals

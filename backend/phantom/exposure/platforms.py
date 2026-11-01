"""What each platform can actually contribute, and where each item stands.

The table is the honest version of a capability list. An item marked
``measured`` is read today by an adapter. ``guarded`` means the concept is in
scope but the file that carries it is ambiguous by name, so it stays refused
until something narrower reads it. ``not_in_export`` and
``adapter_required`` are not failures: they are the difference between "we
chose not to" and "we have not built it".

One rule decides every row: only what the account owner can legitimately access
about their own account, with their own authorization. No row may describe
another person.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

MEASURED = "measured"
GUARDED = "guarded"
NOT_IN_EXPORT = "not_in_export"
ADAPTER_REQUIRED = "adapter_required"
REFUSED = "refused"


@dataclass(frozen=True)
class Contribution:
    platform: str
    contributes: str
    status: str
    detail: str


CONTRIBUTIONS: tuple[Contribution, ...] = (
    # -- Facebook / Meta ---------------------------------------------------
    Contribution(
        "facebook", "profile visibility", NOT_IN_EXPORT,
        "The export lists your fields but not which of them are public. Which "
        "fields are visible is a settings fact, not an export fact, so it needs a "
        "separate settings probe against an allowlisted domain.",
    ),
    Contribution(
        "facebook", "account connections", REFUSED,
        "A Facebook connections export is friends, pages and groups: other people "
        "and the links to them. Refused on the same grounds as the social graph.",
    ),
    Contribution(
        "facebook", "public information", MEASURED,
        "Username, email and phone are read from personal_information.json as your "
        "own public identifiers. Display names are deliberately not read: a chosen "
        "name is not an identifier, and reading it invites name matching.",
    ),
    Contribution(
        "facebook", "connected accounts (self-linked)", GUARDED,
        "A self-linked account is your own identity, so it is in scope. It is not "
        "read yet because 'connections' is a deny marker: Facebook uses that word "
        "for friends, so the guard cannot tell the two apart by name and needs a "
        "narrower reader before it can.",
    ),
    # -- Snapchat ----------------------------------------------------------
    Contribution(
        "snapchat", "discoverability settings", ADAPTER_REQUIRED,
        "No adapter. The export layout has not been verified here, and guessing at "
        "someone else's file layout is how a parser silently misreads it.",
    ),
    Contribution(
        "snapchat", "public profile exposure", ADAPTER_REQUIRED,
        "Same: the public-profile fields need their own adapter and a fixture "
        "before anything is claimed about them.",
    ),
    # -- Discord -----------------------------------------------------------
    Contribution(
        "discord", "profile visibility", MEASURED,
        "username, email, phone and account id are read from account/user.json. "
        "global_name is not read, for the reason given above.",
    ),
    Contribution(
        "discord", "server membership", MEASURED,
        "Server names you belong to, from servers/index.csv, name column only. The "
        "reader refuses the file outright if it carries any column other than id "
        "and name, because a member column is other people.",
    ),
    Contribution(
        "discord", "connected accounts (self-linked)", GUARDED,
        "In scope, and blocked by the same 'connections' marker as Facebook. Needs "
        "a name-only reader with a fixture that proves it cannot pick up a member "
        "list.",
    ),
)

STATUS_MEANING = {
    MEASURED: "read today by an adapter",
    GUARDED: "in scope, blocked by an ambiguous deny marker",
    NOT_IN_EXPORT: "not a fact the export contains",
    ADAPTER_REQUIRED: "in scope, no adapter yet",
    REFUSED: "will not be built",
}


def matrix() -> dict:
    platforms = sorted({row.platform for row in CONTRIBUTIONS})
    return {
        "status_meaning": STATUS_MEANING,
        "platforms": {
            platform: [asdict(row) for row in CONTRIBUTIONS if row.platform == platform]
            for platform in platforms
        },
    }

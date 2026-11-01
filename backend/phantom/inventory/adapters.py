"""Platform export readers.

One platform per adapter, on purpose: each export format is a claim about
someone else's file layout, and pretending a single parser handles all of them
would mean silently misreading whichever one changed.

Everything here reads only what the operator downloaded themselves. There is no
network call in this module and no API client, because a data export is already
an authorised, complete, local copy.
"""
from __future__ import annotations

import json
from pathlib import Path

from phantom.inventory.facets import (
    Facet,
    Reading,
    Refusal,
    extract_keys,
    facet_kind,
    is_denied,
)

#: Discord's data package puts account fields in one of these.
DISCORD_ACCOUNT_FILES = ("account/user.json", "user.json", "account/user.json5")


class ExportNotFound(FileNotFoundError):
    pass


class DiscordExport:
    """Reads the operator's own account facts from a Discord data package."""

    platform = "discord"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    # -- discovery ----------------------------------------------------
    def _candidate_files(self) -> tuple[list[Path], list[Refusal]]:
        if self.path.is_file():
            denied = is_denied(self.path.name)
            if denied is not None:
                raise ExportNotFound(
                    f"{self.path.name} is not an account file: it looks like it "
                    f"describes other people or content ('{denied}'). Point the "
                    "importer at the account file inside the package."
                )
            return [self.path], []

        if not self.path.is_dir():
            raise ExportNotFound(f"{self.path} does not exist")

        found: list[Path] = []
        refusals: list[Refusal] = []
        for relative in DISCORD_ACCOUNT_FILES:
            candidate = self.path / relative
            if candidate.is_file() and candidate not in found:
                found.append(candidate)

        # Everything else in the package is reported, never opened. The count is
        # shown to the operator so the boundary is visible rather than assumed.
        for child in sorted(self.path.rglob("*")):
            if not child.is_file() or child in found:
                continue
            # Match the whole relative path, not just the filename: a data
            # package announces a friends or messages export in the directory
            # name, and index.csv on its own looks innocent.
            relative = str(child.relative_to(self.path))
            marker = is_denied(relative)
            if marker is not None:
                refusals.append(
                    Refusal(
                        item=relative,
                        reason=f"not read: describes other people or content ('{marker}')",
                    )
                )
        if not found:
            raise ExportNotFound(
                "no account file found in that package. Expected one of: "
                + ", ".join(DISCORD_ACCOUNT_FILES)
            )
        return found, refusals

    # -- reading ------------------------------------------------------
    def _collect(self, node, *, kind: str, where: str, depth: int, facets: list, refusals: list) -> None:
        """Gather string leaves under an allowed key, without leaving its subtree."""
        if depth > 3:
            return
        if isinstance(node, (str, int)) and not isinstance(node, bool):
            text = str(node).strip()
            if text:
                facets.append(Facet(kind=kind, value=text, source_field=where))
            return
        if isinstance(node, list):
            for item in node:
                self._collect(item, kind=kind, where=where, depth=depth + 1, facets=facets, refusals=refusals)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                denied = is_denied(str(key))
                if denied is not None:
                    refusals.append(
                        Refusal(item=f"{where}:{key}", reason=f"describes other people or content ('{denied}')")
                    )
                    continue
                self._collect(value, kind=kind, where=where, depth=depth + 1, facets=facets, refusals=refusals)

    def read(self) -> Reading:
        files, refusals = self._candidate_files()
        reading = Reading(platform=self.platform, refusals=list(refusals))

        for file in files:
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ExportNotFound(f"{file.name} is not readable JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ExportNotFound(f"{file.name} is not a JSON object")

            # Discord nests the account under "user" in some exports and not in
            # others. Both shapes are checked, and nothing deeper: a recursive
            # walk would happily wander into message content.
            sources = [("", payload)]
            for key in ("user", "account"):
                nested = payload.get(key)
                if isinstance(nested, dict):
                    sources.append((f"{key}.", nested))

            found_any = False
            for prefix, mapping in sources:
                facets, refused = extract_keys(mapping, where=f"{file.name}:{prefix}")
                for facet in facets:
                    reading.facets.append(
                        Facet(
                            kind=facet.kind,
                            value=facet.value,
                            source_field=f"{prefix}{facet.source_field}",
                        )
                    )
                    found_any = True
                reading.refusals.extend(refused)

            if found_any:
                reading.files_read.append(str(file))

        if not reading.facets:
            raise ExportNotFound(
                "the account file was readable but contained none of the expected "
                "fields (username, email, phone, id). Nothing was stored."
            )
        return reading



#: Containers Meta's export wraps identity in. Structure only: a key in here is
#: descended into, never read as a value.
META_CONTAINER_KEYS = {
    "profile_v2", "profile", "personal_information", "profiles", "users", "account",
}

META_ACCOUNT_FILES = (
    "personal_information/personal_information/personal_information.json",
    "personal_information/personal_information.json",
    "personal_information.json",
    "profile_information/profile_information.json",
)

#: Every other top-level directory Meta ships. Reported, never walked into.
META_KNOWN_OTHER_DIRS = (
    "your_activity_across_facebook", "your_facebook_activity", "messages",
    "followers_and_following", "friends_and_followers", "your_instagram_activity",
    "connections", "logged_information", "security_and_login_information",
    "ads_information", "posts", "comments", "reels", "stories",
)


class MetaExport:
    """Reads the operator's own identity from a Meta download-your-information zip.

    Meta's export buries four useful fields in a large tree of everything else.
    This walks only the containers named in ``META_CONTAINER_KEYS``, to a fixed
    depth, and refuses any key or directory whose name says it holds messages,
    followers, members or activity.
    """

    platform = "meta"

    MAX_DEPTH = 6

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def _candidate_files(self) -> tuple[list[Path], list[Refusal]]:
        if self.path.is_file():
            denied = is_denied(self.path.name)
            if denied is not None:
                raise ExportNotFound(
                    f"{self.path.name} is not an identity file: it looks like it "
                    f"describes other people or content ('{denied}')."
                )
            return [self.path], []

        if not self.path.is_dir():
            raise ExportNotFound(f"{self.path} does not exist")

        found = [self.path / rel for rel in META_ACCOUNT_FILES if (self.path / rel).is_file()]
        refusals: list[Refusal] = []
        for child in sorted(self.path.iterdir()):
            if not child.is_dir():
                continue
            marker = is_denied(child.name)
            if marker is not None:
                refusals.append(
                    Refusal(
                        item=child.name + "/",
                        reason=f"not read: describes other people or content ('{marker}')",
                    )
                )
        if not found:
            raise ExportNotFound(
                "no personal_information file found. Expected one of: "
                + ", ".join(META_ACCOUNT_FILES)
            )
        return found, refusals

    def _walk(self, node, *, where: str, depth: int, facets: list, refusals: list) -> None:
        if depth > self.MAX_DEPTH:
            return
        if isinstance(node, list):
            for item in node:
                self._walk(item, where=where, depth=depth + 1, facets=facets, refusals=refusals)
            return
        if not isinstance(node, dict):
            return

        for key, value in node.items():
            name = str(key)
            denied = is_denied(name)
            if denied is not None:
                refusals.append(
                    Refusal(item=f"{where}:{name}", reason=f"describes other people or content ('{denied}')")
                )
                continue

            kind = facet_kind(name)
            if kind is not None:
                # Meta often nests the list one level down: {emails: {emails: [...]}}.
                # Collect the leaves under an allowed key, refusing anything
                # disqualified on the way down.
                self._collect(
                    value, kind=kind, where=f"{where}:{name}", depth=0,
                    facets=facets, refusals=refusals,
                )
                continue

            if name.lower() in META_CONTAINER_KEYS and isinstance(value, (dict, list)):
                self._walk(
                    value, where=f"{where}:{name}", depth=depth + 1,
                    facets=facets, refusals=refusals,
                )

    def _collect(self, node, *, kind: str, where: str, depth: int, facets: list, refusals: list) -> None:
        """Gather string leaves under an allowed key, without leaving its subtree."""
        if depth > 3:
            return
        if isinstance(node, (str, int)) and not isinstance(node, bool):
            text = str(node).strip()
            if text:
                facets.append(Facet(kind=kind, value=text, source_field=where))
            return
        if isinstance(node, list):
            for item in node:
                self._collect(item, kind=kind, where=where, depth=depth + 1, facets=facets, refusals=refusals)
            return
        if isinstance(node, dict):
            for key, value in node.items():
                denied = is_denied(str(key))
                if denied is not None:
                    refusals.append(
                        Refusal(item=f"{where}:{key}", reason=f"describes other people or content ('{denied}')")
                    )
                    continue
                self._collect(value, kind=kind, where=where, depth=depth + 1, facets=facets, refusals=refusals)

    def read(self) -> Reading:
        files, refusals = self._candidate_files()
        reading = Reading(platform=self.platform, refusals=list(refusals))

        for file in files:
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ExportNotFound(f"{file.name} is not readable JSON: {exc}") from exc

            before = len(reading.facets)
            self._walk(
                payload, where=file.name, depth=0,
                facets=reading.facets, refusals=reading.refusals,
            )
            if len(reading.facets) > before:
                reading.files_read.append(str(file))

        # Meta repeats a value at several depths; one email is one fact.
        unique: list[Facet] = []
        seen: set[tuple[str, str]] = set()
        for facet in reading.facets:
            key = (facet.kind, facet.normalised)
            if key not in seen:
                seen.add(key)
                unique.append(facet)
        reading.facets = unique

        if not reading.facets:
            raise ExportNotFound(
                "the personal_information file was readable but contained none of "
                "the expected fields (username, email, phone, id). Nothing was stored."
            )
        return reading


ADAPTERS = {"discord": DiscordExport, "meta": MetaExport}

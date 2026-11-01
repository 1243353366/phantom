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

from phantom.inventory.facets import Facet, Reading, Refusal, extract_keys, is_denied

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


ADAPTERS = {"discord": DiscordExport}

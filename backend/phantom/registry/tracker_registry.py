"""Tracker / provider identification.

Deliberately conservative: a domain is only named when it is on the curated
list. Everything else stays an unattributed domain node, because inventing an
attribution is worse than showing a gap.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DATA_PATH = Path(__file__).parent / "data" / "trackers.yaml"

# Query parameters that commonly carry a persistent or per-message identifier.
IDENTIFIER_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "mc_eid", "mc_cid", "_hsenc", "_hsmi",
    "mkt_tok", "vero_id", "vero_conv", "oly_anon_id", "oly_enc_id",
    "s_cid", "elqTrackId", "elqaid", "elqat", "pk_campaign", "pk_kwd",
    "sc_cid", "trk", "trkCampaign",
}


@dataclass(frozen=True)
class RegistryEntry:
    domain: str
    name: str
    category: str
    parent: str | None
    source: str


class TrackerRegistry:
    def __init__(self, path: Path = DATA_PATH) -> None:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)["entries"]
        self._entries = [RegistryEntry(**row) for row in raw]

    @property
    def entries(self) -> list[RegistryEntry]:
        return list(self._entries)

    def resolve(self, host: str) -> RegistryEntry | None:
        """Match a hostname against the registry, longest domain first."""
        host = (host or "").lower().strip(".")
        if not host:
            return None
        best: RegistryEntry | None = None
        for entry in self._entries:
            d = entry.domain.lower()
            if host == d or host.endswith("." + d):
                if best is None or len(d) > len(best.domain):
                    best = entry
        return best

    def is_known_tracker_domain(self, host: str) -> bool:
        entry = self.resolve(host)
        return entry is not None

    def classify_identifier_params(self, query: dict[str, list[str]]) -> dict[str, str]:
        found = {}
        for key, values in query.items():
            if key in IDENTIFIER_PARAMS and values:
                found[key] = values[0]
        return found


registry = TrackerRegistry()

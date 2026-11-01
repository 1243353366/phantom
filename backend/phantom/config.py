"""Runtime configuration. Everything is local-first by default."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_HOME = Path(os.environ.get("PHANTOM_HOME", "~/.phantom")).expanduser()


@dataclass(frozen=True)
class Settings:
    """Process-wide settings.

    Nothing here may point at a remote service by accident. The only outbound
    network calls PHANTOM is allowed to make are declared in
    ``selfaudit/egress_allowlist.yaml`` and routed through
    ``phantom.egress``.
    """

    db_url: str = field(
        default_factory=lambda: os.environ.get(
            "PHANTOM_DB_URL", f"sqlite:///{DEFAULT_HOME / 'phantom.db'}"
        )
    )
    home: Path = field(default_factory=lambda: DEFAULT_HOME)
    key_file: Path = field(
        default_factory=lambda: DEFAULT_HOME / "local-hmac.key"
    )
    egress_log: Path = field(
        default_factory=lambda: DEFAULT_HOME / "egress.jsonl"
    )
    # Gmail OAuth. Metadata scope only - PHANTOM never requests message bodies.
    gmail_scopes: tuple[str, ...] = (
        "https://www.googleapis.com/auth/gmail.metadata",
        "openid",
        "email",
    )
    # Correlation rules need this many independent observations before an edge
    # may be upgraded from "hypothesized" to "correlated".
    correlation_threshold: int = 2
    retention_days: int = 90

    # --- counter-observation -----------------------------------------
    #: Where your canaries live. Point this at the host you control.
    mirror_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "PHANTOM_MIRROR_BASE_URL", "http://127.0.0.1:8000"
        )
    )
    #: Off by default. An HMAC of the source address is enough to correlate
    #: repeat visitors without keeping an address book of everyone who probed.
    retain_raw_ip: bool = field(
        default_factory=lambda: os.environ.get("PHANTOM_RETAIN_RAW_IP", "0") == "1"
    )
    #: Bounded tarpit. 0 disables it. The cap exists so a honeypot can never be
    #: turned into a resource-exhaustion weapon against PHANTOM itself.
    tarpit_ms_max: int = field(
        default_factory=lambda: int(os.environ.get("PHANTOM_TARPIT_MS_MAX", "0"))
    )
    #: A canary URL is public by design, so anything that can be fetched can be
    #: fetched repeatedly. Without a budget, the most sensitive table in the
    #: system grows at whatever rate a stranger chooses.
    canary_max_observations_per_token: int = field(
        default_factory=lambda: int(
            os.environ.get("PHANTOM_CANARY_MAX_OBSERVATIONS_PER_TOKEN", "500")
        )
    )
    canary_max_per_hour_per_token: int = field(
        default_factory=lambda: int(os.environ.get("PHANTOM_CANARY_MAX_PER_HOUR", "60"))
    )
    mirror_retention_days: int = field(
        default_factory=lambda: int(os.environ.get("PHANTOM_MIRROR_RETENTION_DAYS", "30"))
    )
    #: Optional local ASN table (CSV: prefix,asn,organisation). Looked up on
    #: disk; PHANTOM never calls a third-party IP-intelligence API, because a
    #: canary hit is exactly the wrong thing to hand to someone else.
    asn_db: Path = field(
        default_factory=lambda: DEFAULT_HOME / "asn.csv"
    )


settings = Settings()

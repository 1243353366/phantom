"""Retention that runs without being asked.

An expiry that only happens when someone remembers to run a command is not a
retention policy, it is a retention intention. Every promise in the docs gets a
line here, and this module is called on service start as well as by
``phantom retention``.
"""
from __future__ import annotations

from sqlalchemy.orm import Session


def enforce_all(session: Session) -> dict:
    """Apply every stated expiry. Idempotent, safe to run on every start."""
    from phantom.auth.consent import ConsentService
    from phantom.egress import scrub_legacy_log
    from phantom.mirror.beacon import purge_expired

    purged = purge_expired(session)
    cleared = ConsentService(session).clear_expired()
    scrubbed = scrub_legacy_log()
    return {
        "canary_observations_purged": purged,
        "consent_values_cleared": cleared,
        "egress_log_lines_scrubbed": scrubbed,
    }

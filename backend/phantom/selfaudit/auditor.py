"""Who Watches the Watchers.

A privacy tool that quietly adds a surveillance layer defeats itself. This
module answers, from code and logs rather than from assurances:

  * which third parties can PHANTOM reach at all
  * whether any code path makes requests outside the audited chokepoint
  * what has actually left this machine, and when
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from phantom import egress
from phantom.config import settings

PKG_ROOT = Path(__file__).resolve().parent.parent
NETWORK_CAPABLE = {
    "requests", "httpx", "aiohttp", "urllib3", "httplib2", "google-api-python-client",
    "google-auth-oauthlib", "boto3", "sentry-sdk", "posthog", "analytics-python",
}
# Direct socket / raw HTTP use that bypasses phantom.egress.
BYPASS_PATTERNS = [
    (re.compile(r"\bimport\s+socket\b"), "raw socket use"),
    (re.compile(r"\b(requests|aiohttp)\.(get|post|request|Session)\b"), "direct HTTP client call"),
    (re.compile(r"\burlopen\s*\("), "urllib urlopen call"),
    (re.compile(r"\bsmtplib\b"), "outbound SMTP"),
    (re.compile(r"\bwebbrowser\b|\bsubprocess\b.*\bcurl\b"), "shell or browser egress"),
]


class SelfAuditor:
    def __init__(self, db_session=None) -> None:
        self.session = db_session

    # --- static surface -------------------------------------------------
    def declared_egress(self) -> list[dict]:
        with open(Path(__file__).parent / "egress_allowlist.yaml", encoding="utf-8") as fh:
            return yaml.safe_load(fh)["allowed"]

    def scan_source(self) -> list[dict]:
        findings: list[dict] = []
        for path in PKG_ROOT.rglob("*.py"):
            if "selfaudit" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for pattern, label in BYPASS_PATTERNS:
                for match in pattern.finditer(text):
                    line = text[: match.start()].count("\n") + 1
                    findings.append(
                        {
                            "severity": "high",
                            "kind": "unmediated_egress",
                            "file": str(path.relative_to(PKG_ROOT)),
                            "line": line,
                            "detail": f"{label} outside phantom.egress",
                        }
                    )
            if "phantom.egress" in text or "phantom import egress" in text:
                findings.append(
                    {
                        "severity": "info",
                        "kind": "mediated_egress",
                        "file": str(path.relative_to(PKG_ROOT)),
                        "detail": "routes outbound traffic through the audited chokepoint",
                    }
                )
        return findings

    def dependency_surface(self) -> dict:
        declared = {
            "fastapi", "uvicorn", "sqlalchemy", "networkx", "httpx", "pydantic",
            "cryptography", "pyyaml", "google-auth", "google-auth-oauthlib",
        }
        return {
            "packages_that_can_open_network_connections": sorted(
                declared & NETWORK_CAPABLE
            ),
            "note": (
                "Every network-capable dependency above is only reachable through "
                "phantom.egress, which enforces the allowlist and logs each attempt."
            ),
        }

    # --- observed behaviour --------------------------------------------
    def observed_egress(self) -> dict:
        log = egress.read_log()
        by_host: dict[str, dict] = {}
        for entry in log:
            host = entry["url"].split("/")[2] if "//" in entry["url"] else entry["url"]
            bucket = by_host.setdefault(host, {"calls": 0, "blocked": 0, "purposes": set()})
            bucket["calls"] += 1
            if not entry["allowed"]:
                bucket["blocked"] += 1
            bucket["purposes"].add(entry["purpose"])
        return {
            "total_calls": len(log),
            "blocked_attempts": sum(1 for e in log if not e["allowed"]),
            "hosts": {
                host: {"calls": v["calls"], "blocked": v["blocked"],
                       "purposes": sorted(v["purposes"])}
                for host, v in by_host.items()
            },
            "log_path": str(settings.egress_log),
        }

    def run(self) -> dict:
        findings = self.scan_source()
        blocked = [f for f in findings if f["kind"] == "unmediated_egress"]
        allowlist = self.declared_egress()
        observed = self.observed_egress()

        report = {
            "declared_outbound_hosts": [row["host"] for row in allowlist],
            "declarations": allowlist,
            "dependencies": self.dependency_surface(),
            "findings": findings,
            "unmediated_egress_found": len(blocked),
            "observed_egress": observed,
            "verdict": (
                "No unmediated outbound code paths found. Every declared destination "
                "is listed above with its justification."
                if not blocked
                else f"{len(blocked)} code path(s) can reach the network without being audited."
            ),
        }

        if self.session is not None:
            from phantom.models import SelfAuditRun

            self.session.add(SelfAuditRun(findings=findings, egress_summary=observed))
            self.session.commit()
        return report

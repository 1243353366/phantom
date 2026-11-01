"""Local relationship exposure analysis.

The deliberate constraint: this module never leaves the machine and never
builds a social graph. It answers one narrow question - "do the organisations in
my own address book also show up in the tracking infrastructure I observe?" -
using domains only.

It does not upload contacts, does not store names, does not store phone numbers,
and does not infer that two people know each other. A contact record is treated
as *the user knows this address*, which is categorically different from a
technical relationship.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom import crypto
from phantom.models import Edge, Node
from phantom.registry.tracker_registry import registry

RELATION_KINDS = {
    "contact_record": "You have this address in your own contacts. Nothing more.",
    "technical_relationship": "Observed infrastructure link between two domains.",
    "communication_relationship": "You have corresponded with this address.",
    "speculative_association": "Suggested by pattern only. Unverified.",
}

EMAIL_RE = re.compile(r"[^@\s,;]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().-]{5,20}$")


@dataclass
class ContactRecord:
    email_domain: str | None = None
    has_phone: bool = False
    label: str | None = None


@dataclass
class ExposureResult:
    contacts_scanned: int = 0
    domains_seen: int = 0
    intersections: list[dict] = field(default_factory=list)
    excluded: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "contacts_scanned": self.contacts_scanned,
            "distinct_contact_domains": self.domains_seen,
            "intersections": self.intersections,
            "excluded": self.excluded,
            "notes": self.notes,
            "relation_kinds": RELATION_KINDS,
        }


def parse_csv(text: str) -> list[ContactRecord]:
    """Read a contact export the user made themselves.

    Understands a permissive shape: any column whose value looks like an email
    contributes its domain; any column that looks like a phone number sets a
    boolean. Names and raw values are dropped immediately and never returned.
    """
    records: list[ContactRecord] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        domain = None
        has_phone = False
        for cell in row:
            cell = (cell or "").strip()
            if not cell:
                continue
            m = EMAIL_RE.search(cell)
            if m:
                domain = m.group(1).lower()
                continue
            if PHONE_RE.match(cell) and sum(c.isdigit() for c in cell) >= 7:
                has_phone = True
        if domain or has_phone:
            records.append(ContactRecord(email_domain=domain, has_phone=has_phone))
    return records


class ContactExposureAnalyzer:
    def __init__(self, session: Session) -> None:
        self.session = session

    def _ecosystem_domains(self) -> dict[str, str]:
        """Domain -> why it is in the observed ecosystem."""
        out: dict[str, str] = {}
        for node in self.session.scalars(select(Node).where(Node.kind == "domain")):
            role = node.attrs.get("role", "observed")
            out[node.label] = f"seen as {role} in an authorised message"
        for edge in self.session.scalars(
            select(Edge).where(Edge.rule_id.in_(["R-OBS-2", "R-COR-1"]))
        ):
            out.setdefault(edge.src_key.replace("org:domain:", ""), "sender in your observed ecosystem")
        return out

    def analyze(
        self,
        records: list[ContactRecord],
        *,
        exclude_domains: set[str] | None = None,
        exclude_categories: set[str] | None = None,
    ) -> ExposureResult:
        exclude_domains = {d.lower() for d in (exclude_domains or set())}
        exclude_categories = set(exclude_categories or set())
        result = ExposureResult(contacts_scanned=len(records))

        ecosystem = self._ecosystem_domains()
        provider_categories = {
            n.label: n.attrs.get("category", "")
            for n in self.session.scalars(select(Node).where(Node.kind == "provider"))
        }

        domains: set[str] = set()
        for record in records:
            if record.email_domain:
                domains.add(record.email_domain)
        result.domains_seen = len(domains)

        skipped: dict[str, int] = {}
        for domain in sorted(domains):
            if domain in exclude_domains:
                skipped["user excluded"] = skipped.get("user excluded", 0) + 1
                continue
            entry = registry.resolve(domain)
            if entry and entry.category in exclude_categories:
                skipped[f"category excluded: {entry.category}"] = (
                    skipped.get(f"category excluded: {entry.category}", 0) + 1
                )
                continue

            reason = None
            if domain in ecosystem:
                reason = ecosystem[domain]
            elif entry:
                reason = f"domain is attributed to {entry.name} ({entry.category})"

            if reason:
                result.intersections.append(
                    {
                        # A domain, never a person. Pseudonymous by design.
                        "domain_token": crypto.hmac_hex(domain, domain="contact-domain")[:16],
                        "domain": domain,
                        "why": reason,
                        "provider": entry.name if entry else None,
                        "category": entry.category if entry else provider_categories.get(domain),
                        "relation": "contact_record",
                        "interpretation": RELATION_KINDS["contact_record"],
                        "confidence_note": (
                            "You know someone at this domain and this domain also "
                            "appears in your observed tracking infrastructure. That "
                            "is a coincidence of infrastructure, not evidence about "
                            "the person."
                        ),
                    }
                )

        result.excluded = skipped
        result.notes = [
            "Analysis ran entirely on this machine. No contact left it.",
            "Names, raw email addresses and phone numbers were discarded before matching.",
            "A shared domain is a technical coincidence, not a statement about anyone you know.",
        ]
        return result

    def analyze_csv(self, text: str, **kwargs) -> ExposureResult:
        return self.analyze(parse_csv(text), **kwargs)

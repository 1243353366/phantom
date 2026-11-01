"""Evidence-backed relationship construction.

The engine is the only writer of edges. It refuses to create one without at
least one :class:`~phantom.models.Evidence` row, which is what makes the
"every graph edge has provenance" requirement enforceable rather than aspirational.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.collector.headers import ParsedEmail
from phantom.config import settings
from phantom.engine import classify
from phantom.models import Edge, Evidence, Node
from phantom.registry.tracker_registry import registry

LEGAL_SUFFIX = re.compile(
    r"\b(inc|llc|ltd|limited|corp|corporation|co|gmbh|plc|sa|ag|bv|oy|ab)\b\.?",
    re.IGNORECASE,
)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_identity(name: str) -> str:
    """Loose org label used only for continuity hypotheses, never for matching edges."""
    text = LEGAL_SUFFIX.sub("", (name or "").lower())
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


class RelationshipEngine:
    def __init__(self, session: Session) -> None:
        self.session = session

    # ------------------------------------------------------------------
    # nodes
    # ------------------------------------------------------------------
    def _node(self, key: str, kind: str, label: str, attrs: dict | None = None) -> str:
        existing = self.session.scalar(select(Node).where(Node.key == key))
        if existing is None:
            self.session.add(
                Node(key=key, kind=kind, label=label, attrs=attrs or {}, last_seen=_now())
            )
        else:
            existing.last_seen = _now()
            if attrs:
                existing.attrs = {**existing.attrs, **attrs}
        return key

    # ------------------------------------------------------------------
    # edges
    # ------------------------------------------------------------------
    def _edge(
        self,
        rule_id: str,
        src_key: str,
        dst_key: str,
        *,
        evidence_kind: str,
        detail: str,
        source_ref: str,
        payload: dict | None = None,
        base_confidence: float = 0.5,
        observed_at: dt.datetime | None = None,
        confirmed: bool = False,
    ) -> Edge:
        rule = classify.RULES[rule_id]
        if rule.requires_confirmation and not confirmed:
            # Ingestion is not allowed to join the layers. A cross-layer edge
            # needs a human, and that decision lives in shadow.bridges.
            raise classify.UnconfirmedCrossLayerEdge(
                f"{rule_id} joins the surveillance and adversarial layers and "
                "cannot be written by ingestion"
            )
        edge = self.session.scalar(
            select(Edge).where(
                Edge.src_key == src_key,
                Edge.dst_key == dst_key,
                Edge.relation == rule.relation,
            )
        )
        if edge is None:
            edge = Edge(
                src_key=src_key,
                dst_key=dst_key,
                relation=rule.relation,
                classification=rule.classification,
                rule_id=rule.id,
                confidence=classify.confidence_for(rule.classification, 1, base_confidence),
                observation_count=1,
                caveat=rule.caveat,
            )
            self.session.add(edge)
            self.session.flush()
            already = False
        else:
            already = any(
                e.kind == evidence_kind and e.source_ref == source_ref for e in edge.evidence
            )
            if not already:
                edge.observation_count += 1
                edge.last_seen = _now()
                edge.confidence = classify.confidence_for(
                    edge.classification, edge.observation_count, base_confidence
                )

        if not already:
            self.session.add(
                Evidence(
                    edge_id=edge.id,
                    kind=evidence_kind,
                    detail=detail,
                    source_ref=source_ref,
                    snippet_hash=_hash(detail),
                    observed_at=observed_at or _now(),
                    payload=payload or {},
                )
            )
        return edge

    # ------------------------------------------------------------------
    # ingestion
    # ------------------------------------------------------------------
    def ingest(self, mail: ParsedEmail, *, source_ref: str) -> dict:
        """Fold one parsed message into the graph. Idempotent per source_ref."""
        at = mail.sent_at or _now()
        meta = {"message_ref": source_ref, "sent_at": at.isoformat()}
        org_key = None
        if mail.from_domain:
            org_key = self._node(
                f"org:domain:{mail.from_domain}",
                "organization",
                f"{mail.display_name} ({mail.from_domain})" if mail.display_name
                else mail.from_domain,
                {
                    "identity": normalize_identity(mail.display_name),
                    "domain": mail.from_domain,
                    "role": "sender",
                },
            )

        pixel_domains: set[str] = set()
        provider_hits: dict[str, set[str]] = defaultdict(set)

        if org_key:
            for px in mail.pixels:
                self._node(
                    f"domain:{px.host}", "domain", px.host,
                    {"role": "tracking-content", "reasons": px.reasons},
                )
                pixel_domains.add(px.host)
                self._edge(
                    "R-OBS-1", org_key, f"domain:{px.host}",
                    evidence_kind="tracking_pixel",
                    detail=f"Tracking pixel served from {px.host} ({'; '.join(px.reasons)})",
                    source_ref=f"{source_ref}:pixel:{px.host}",
                    payload={"url": px.url, "reasons": px.reasons,
                             "size": [px.width, px.height], **meta},
                    base_confidence=px.confidence,
                    observed_at=at,
                )
                entry = registry.resolve(px.host)
                if entry:
                    self._provider(org_key, entry, source_ref, f"{source_ref}:px-provider:{px.host}", at)
                    provider_hits[entry.name].add(px.host)

            for link in mail.links:
                if link.is_redirector:
                    self._node(f"domain:{link.host}", "domain", link.host, {"role": "redirector"})
                    self._edge(
                        "R-OBS-4", org_key, f"domain:{link.host}",
                        evidence_kind="click_redirector",
                        detail=f"Click target rewritten through {link.host}",
                        source_ref=f"{source_ref}:redir:{link.host}",
                        payload={"url": link.url, "reasons": link.reasons,
                                 "chain_length": len(mail.redirector_hosts), **meta},
                        base_confidence=0.8,
                        observed_at=at,
                    )
                    entry = registry.resolve(link.host)
                    if entry:
                        self._provider(org_key, entry, source_ref, f"{source_ref}:redir-provider:{link.host}", at)
                        provider_hits[entry.name].add(link.host)
                if link.target_host:
                    self._node(f"domain:{link.target_host}", "domain", link.target_host,
                               {"role": "landing"})
                    entry = registry.resolve(link.target_host)
                    if entry:
                        self._provider(org_key, entry, source_ref,
                                       f"{source_ref}:target-provider:{link.target_host}", at)

            for host in mail.relay_hosts:
                if host == mail.from_domain:
                    continue
                self._node(f"host:{host}", "mail_host", host, {"role": "relay"})
                self._edge(
                    "R-OBS-3", org_key, f"host:{host}",
                    evidence_kind="relay_hop",
                    detail=f"Mail traversed {host}",
                    source_ref=f"{source_ref}:relay:{host}",
                    base_confidence=0.35,
                    payload=dict(meta),
                    observed_at=at,
                )

            for domain in dict.fromkeys(mail.reply_to_domains + ([mail.return_path_domain] if mail.return_path_domain else [])):
                if domain == mail.from_domain:
                    continue
                self._node(f"domain:{domain}", "domain", domain, {"role": "routing"})
                self._edge(
                    "R-OBS-5", org_key, f"domain:{domain}",
                    evidence_kind="routing_header",
                    detail=f"Routing header points at {domain}",
                    source_ref=f"{source_ref}:routing:{domain}",
                    base_confidence=0.6,
                    payload=dict(meta),
                    observed_at=at,
                )

        for sign in mail.dkim:
            if not sign.get("domain"):
                continue
            self._node(
                f"dkim:{sign['domain']}:{sign.get('selector') or 'unknown'}",
                "dkim_identity",
                f"{sign['domain']} / {sign.get('selector') or '?'}",
                {"selector": sign.get("selector")},
            )

        self.session.commit()

        verdicts = [r for r in mail.auth_results if r["mechanism"] == "dmarc"]
        return {
            "sender_domain": mail.from_domain,
            "pixels": len(mail.pixels),
            "redirectors": len(mail.redirector_hosts),
            "providers": sorted(provider_hits),
            "pixel_domains": sorted(pixel_domains),
            "dmarc": verdicts[0]["result"] if verdicts else "unknown",
        }

    def _provider(self, org_key: str, entry, source_ref: str, ref: str,
                  observed_at: dt.datetime | None = None) -> None:
        """One message contributes at most one observation per provider.

        A single email often resolves the same provider through both a pixel
        and a redirect. Counting that as two observations would inflate
        confidence on the strength of one message, so the evidence key is scoped
        to the message rather than to the individual host that revealed it.
        """
        self._node(
            f"provider:{entry.name}", "provider", entry.name,
            {
                "category": entry.category,
                "parent": entry.parent,
                "source": entry.source,
                "domains": [entry.domain],
            },
        )
        message_ref = source_ref.split(":provider:")[0]
        self._edge(
            "R-OBS-2", org_key, f"provider:{entry.name}",
            evidence_kind="registry_match",
            detail=f"{entry.domain} attributed to {entry.name} ({entry.category}) per {entry.source}",
            source_ref=f"{message_ref}:provider:{entry.name}",
            payload={"registry_domain": entry.domain, "category": entry.category,
                     "message_ref": message_ref, "revealed_by": ref},
            base_confidence=0.85,
            observed_at=observed_at,
        )

    # ------------------------------------------------------------------
    # cross-message reasoning
    # ------------------------------------------------------------------
    def correlate(self) -> dict:
        """Run correlation and hypothesis passes over everything ingested so far."""
        created = {"correlated": 0, "hypothesized": 0}
        threshold = settings.correlation_threshold

        # R-COR-1: recurring overlap on one provider across independent senders.
        provider_orgs: dict[str, dict[str, int]] = defaultdict(dict)
        for edge in self.session.scalars(
            select(Edge).where(Edge.rule_id == "R-OBS-2", Edge.classification == classify.OBSERVED)
        ):
            provider_orgs[edge.dst_key][edge.src_key] = edge.observation_count

        for provider_key, orgs in provider_orgs.items():
            if len(orgs) < 2:
                continue
            for i, a in enumerate(sorted(orgs)):
                for b in sorted(orgs)[i + 1:]:
                    overlap = min(orgs[a], orgs[b])
                    if overlap < threshold:
                        continue
                    self._edge(
                        "R-COR-1", a, b,
                        evidence_kind="recurring_overlap",
                        detail=(
                            f"{overlap} independent messages from each side touched "
                            f"{provider_key.split(':', 1)[1]}"
                        ),
                        source_ref=f"corr:{provider_key}:{overlap}",
                        base_confidence=0.55,
                    )
                    created["correlated"] += 1

        # R-HYP-2: shared DKIM selector under the same provider.
        selector_orgs: dict[str, set[str]] = defaultdict(set)
        for sign in self.session.scalars(select(Node).where(Node.kind == "dkim_identity")):
            if sign.attrs.get("selector"):
                selector_orgs[f"dkim:{sign.attrs['selector']}"].add(sign.key)
        # Selector sharing alone cannot link two orgs without a domain bridge,
        # so this pass only annotates nodes; the hypothesis needs R-HYP-1 below.

        # R-HYP-1: one identity presented from more than one domain over time.
        identity_domains: dict[str, set[str]] = defaultdict(set)
        for node in self.session.scalars(select(Node).where(Node.kind == "organization")):
            ident = node.attrs.get("identity") or ""
            if ident:
                identity_domains[ident].add(node.attrs.get("domain", ""))
        for ident, domains in identity_domains.items():
            domains = {d for d in domains if d}
            if len(domains) < 2:
                continue
            ordered = sorted(domains)
            for i, a in enumerate(ordered):
                for b in ordered[i + 1:]:
                    self._edge(
                        "R-HYP-1", f"org:domain:{a}", f"org:domain:{b}",
                        evidence_kind="identity_continuity",
                        detail=f"Both domains presented the sender identity '{ident}'",
                        source_ref=f"hyp1:{ident}:{a}:{b}",
                        base_confidence=0.4,
                    )
                    created["hypothesized"] += 1

        self.session.commit()
        return created

    def unresolved(self) -> dict:
        """Negative-space input: what the graph still cannot attribute."""
        domains = list(self.session.scalars(select(Node).where(Node.kind == "domain")))
        unknown = [d.label for d in domains if registry.resolve(d.label) is None]
        orgs = list(self.session.scalars(select(Node).where(Node.kind == "organization")))
        unlabeled = [o.key for o in orgs if not any(e.rule_id == "R-OBS-2" for e in self._edges_from(o.key))]
        return {
            "unattributed_domains": sorted(unknown),
            "organizations_without_attributed_provider": sorted(unlabeled),
        }

    # ------------------------------------------------------------------
    # Public aliases. The counter-observation graph writes through these so that
    # the "the engine is the only writer of edges" invariant stays true.
    # ------------------------------------------------------------------
    node = _node
    edge = _edge

    def _edges_from(self, key: str):
        return list(self.session.scalars(select(Edge).where(Edge.src_key == key)))

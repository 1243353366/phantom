"""What an observer could join together, from the operator's own accounts only.

The useful output is not a list of accounts, it is the answer to one question:
which of my presences are already linked by something I published, and what did
the linking. A handle reused across platforms is a join key anyone can test in a
search box.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from phantom.models import Edge, Node


def _cluster(presence_keys: list[str], edges: list[Edge]) -> list[list[str]]:
    """Union-find over presences joined by any shared identifier or handle."""
    parent = {key: key for key in presence_keys}

    def find(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # presence -> identifier -> presence, so two presences sharing an identifier
    # land in the same cluster without needing an explicit pairwise edge.
    by_identifier: dict[str, list[str]] = {}
    for edge in edges:
        if edge.relation == "uses_identifier":
            by_identifier.setdefault(edge.dst_key, []).append(edge.src_key)
        elif edge.relation == "shares_handle":
            union(edge.src_key, edge.dst_key)

    for members in by_identifier.values():
        for other in members[1:]:
            union(members[0], other)

    clusters: dict[str, list[str]] = {}
    for key in presence_keys:
        clusters.setdefault(find(key), []).append(key)
    return sorted(clusters.values(), key=len, reverse=True)


def build(session: Session) -> dict:
    presences = list(session.scalars(select(Node).where(Node.kind == "presence")))
    if not presences:
        return {
            "platforms": [],
            "clusters": [],
            "findings": [],
            "note": "No own-account inventory has been imported yet.",
        }

    keys = [node.key for node in presences]
    edges = list(session.scalars(select(Edge)))

    presence_platform = {
        node.key: node.attrs.get("platform", "?")
        for node in session.scalars(select(Node).where(Node.kind == "presence"))
    }
    identifier_kind = {
        node.key: node.attrs.get("kind", "identifier")
        for node in session.scalars(select(Node).where(Node.kind == "identifier"))
    }
    def _source_refs(edge) -> list[str]:
        """Provenance lives on the edge's evidence rows, not on the edge itself."""
        return sorted({row.source_ref for row in getattr(edge, "evidence", []) if row.source_ref})

    identifiers_by_presence: dict[str, list] = {}
    for edge in session.scalars(select(Edge).where(Edge.relation == "uses_identifier")):
        identifiers_by_presence.setdefault(edge.src_key, []).append(edge)
    handle_edges = list(session.scalars(select(Edge).where(Edge.relation == "shares_handle")))

    communities_by_presence: dict[str, list[str]] = {}
    labels = {node.key: node.label for node in session.scalars(select(Node).where(Node.kind == "community"))}
    for edge in session.scalars(select(Edge).where(Edge.relation == "member_of")):
        communities_by_presence.setdefault(edge.src_key, []).append(
            labels.get(edge.dst_key, edge.dst_key)
        )

    clusters = []
    findings = []
    for members in _cluster(keys, edges):
        platforms = sorted({node.attrs.get("platform", "?") for node in presences if node.key in members})
        handles = sorted({node.attrs.get("handle", "?") for node in presences if node.key in members})
        joining = sorted(
            {
                edge.relation
                for edge in edges
                if edge.src_key in members and edge.dst_key in members
                and edge.relation == "shares_handle"
            }
        )
        # What actually joins these accounts, with the evidence behind it, so a
        # shared email is never mistaken for a reused handle.
        evidence: list[dict] = []
        grouped: dict[str, list] = {}
        for key in members:
            for edge in identifiers_by_presence.get(key, []):
                grouped.setdefault(edge.dst_key, []).append(edge)
        for identifier_key, edges in sorted(grouped.items()):
            users = {presence_platform.get(edge.src_key, "?") for edge in edges}
            if len(users) < 2:
                continue
            evidence.append(
                {
                    "rule": "R-INV-1",
                    "kind": "identifier",
                    "identifier_kind": identifier_kind.get(identifier_key, "identifier"),
                    "platforms": sorted(users),
                    "confidence": min(float(getattr(e, "confidence", 1.0) or 1.0) for e in edges),
                    "source_refs": sorted({ref for e in edges for ref in _source_refs(e)}),
                }
            )
        for edge in handle_edges:
            if edge.src_key not in members or edge.dst_key not in members:
                continue
            evidence.append(
                {
                    "rule": "R-INV-2",
                    "kind": "handle",
                    "identifier_kind": "handle",
                    "platforms": sorted(
                        {presence_platform.get(edge.src_key, "?"), presence_platform.get(edge.dst_key, "?")}
                    ),
                    "confidence": float(getattr(edge, "confidence", 0.0) or 0.0),
                    "source_refs": _source_refs(edge),
                }
            )

        kinds = {row["kind"] for row in evidence}
        if kinds == {"identifier", "handle"}:
            link, link_class = "shared_identifier_and_handle", "observed+correlated"
        elif kinds == {"identifier"}:
            link, link_class = "shared_identifier", "observed"
        elif kinds == {"handle"}:
            link, link_class = "reused_handle", "correlated"
        else:
            link, link_class = "none", "none"

        communities = sorted(
            {name for key in members for name in communities_by_presence.get(key, [])}
        )
        clusters.append(
            {
                "platforms": platforms,
                "handles": handles,
                "accounts": len(members),
                "stitchable": len(platforms) > 1 and bool(evidence),
                "joined_by": joining,
                "link": link,
                "link_class": link_class,
                "confidence": round(min((row["confidence"] for row in evidence), default=0.0), 3),
                "evidence": evidence,
                "not_proof_of_ownership": (
                    "Two accounts carrying the same identifier shows the same value "
                    "appears on both. It does not prove one person controls them: a "
                    "shared household address, a recycled handle or a company number "
                    "produce identical evidence."
                ),
                "communities": communities,
            }
        )
        if communities:
            findings.append(
                f"Reachable through {len(communities)} community "
                f"{'name' if len(communities) == 1 else 'names'}: "
                f"{', '.join(communities[:5])}. Member lists are public in some "
                "servers, and a community can name an interest or an affiliation "
                "on its own."
            )
        if len(platforms) > 1:
            findings.append(
                f"{len(platforms)} accounts ({', '.join(platforms)}) are joinable "
                f"through the handle '{handles[0]}'. Anyone who finds one can test "
                "the same string on the others."
            )

    identifiers = list(session.scalars(select(Node).where(Node.kind == "identifier")))
    return {
        "platforms": sorted({node.attrs.get("platform", "?") for node in presences}),
        "accounts": len(presences),
        "identifiers_held": len(identifiers),
        "clusters": clusters,
        "communities": sorted({name for names in communities_by_presence.values() for name in names}),
        "findings": findings,
        "note": (
            "Handles are matched as exact strings after removing separators. A "
            "join that is not listed may still exist; this reports what the "
            "export proves, not what an observer could guess."
        ),
    }

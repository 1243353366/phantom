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
        clusters.append(
            {
                "platforms": platforms,
                "handles": handles,
                "accounts": len(members),
                "stitchable": len(platforms) > 1,
                "joined_by": joining,
            }
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
        "findings": findings,
        "note": (
            "Handles are matched as exact strings after removing separators. A "
            "join that is not listed may still exist; this reports what the "
            "export proves, not what an observer could guess."
        ),
    }

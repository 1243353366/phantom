"""Human-readable output. Markdown because it renders everywhere and diffs well."""
from __future__ import annotations

import datetime as dt

CLASS_GLYPH = {"observed": "solid", "correlated": "double", "hypothesized": "dashed"}


def render_markdown(graph: dict, negative: dict, audit: dict) -> str:
    stats = graph["stats"]
    by_class = stats["edges_by_classification"]
    lines = [
        "# PHANTOM observation report",
        "",
        f"Generated {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC} from authorised "
        "message metadata only.",
        "",
        "## Graph",
        "",
        f"- Nodes: {stats['nodes']}",
        f"- Edges: {stats['edges']} "
        f"(observed {by_class.get('observed', 0)}, correlated {by_class.get('correlated', 0)}, "
        f"hypothesized {by_class.get('hypothesized', 0)})",
        f"- Density: {stats['density']}",
        "",
    ]

    if stats["top_connectors"]:
        lines += ["### Most connected", "", "| Node | Kind | Degree |", "| --- | --- | --- |"]
        kinds = {
            el["data"]["id"]: el["data"].get("kind")
            for el in graph["elements"]
            if "source" not in el["data"]
        }
        for row in stats["top_connectors"]:
            lines.append(f"| `{row['label']}` | {kinds.get(row['key'], '')} | {row['degree']} |")
        lines.append("")

    lines += ["### Relationships", "", "| From | Relation | To | Class | Confidence | Evidence |",
              "| --- | --- | --- | --- | --- | --- |"]
    for el in graph["elements"]:
        d = el["data"]
        if "relation" not in d:
            continue
        lines.append(
            f"| `{d['source']}` | {d['relation']} | `{d['target']}` | "
            f"**{d['classification']}** | {d['confidence']} | {d['evidence_count']} |"
        )
    lines.append("")

    if graph.get("caveats"):
        lines += ["### Standing caveats", ""]
        for caveat in graph["caveats"]:
            lines.append(f"- {caveat}")
        lines.append("")

    lines += [
        "## Negative space",
        "",
        f"{negative['total']} recorded change(s) in observability.",
        "",
    ]
    for event in negative["events"][:20]:
        lines.append(
            f"- `{event['change']}` on `{event['node']}` for `{event['subject']}` "
            f"between {str(event['window_from'])[:10]} and {str(event['window_to'])[:10]} "
            "(cause unknown)"
        )
    if negative["events"]:
        lines.append("")
        lines.append(f"> {negative['interpretation']}")
    lines.append("")

    lines += [
        "## Self-audit: PHANTOM's own footprint",
        "",
        f"- Declared outbound hosts: {', '.join(audit['declared_outbound_hosts'])}",
        f"- Unmediated network paths found: {audit['unmediated_egress_found']}",
        f"- Outbound calls made: {audit['observed_egress']['total_calls']} "
        f"(blocked: {audit['observed_egress']['blocked_attempts']})",
        f"- Verdict: {audit['verdict']}",
        "",
    ]
    return "\n".join(lines)

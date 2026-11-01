import { useEffect, useRef, useState } from "react";
import cytoscape, { Core, EdgeSingular } from "cytoscape";
import { api, EdgeDetail, GraphPayload } from "../lib/api";
import { palette } from "../lib/theme";

const buildStyle = (): cytoscape.StylesheetStyle[] => {
  const p = palette();
  return [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "font-size": 9,
      "text-valign": "bottom",
      "text-margin-y": 4,
      color: p.inkMuted,
      "background-color": p.surface2,
      "border-width": 1,
      "border-color": p.line,
      width: 18,
      height: 18,
    },
  },
  { selector: 'node[kind="organization"]', style: { shape: "round-rectangle", width: 26, height: 26, "background-color": p.accent, "border-color": p.accent, color: p.ink } },
  { selector: 'node[kind="provider"]', style: { shape: "diamond", width: 22, height: 22, "background-color": p.accentSoft } },
  { selector: 'node[kind="mail_host"]', style: { shape: "triangle", width: 14, height: 14 } },
  { selector: 'node[kind="dkim_identity"]', style: { shape: "hexagon" } },
  { selector: "node:selected", style: { "border-width": 2, "border-color": p.accent } },
  {
    selector: "edge",
    style: {
      width: 1.2,
      "line-color": p.lineStrong,
      "target-arrow-color": p.lineStrong,
      "target-arrow-shape": "triangle",
      "arrow-scale": 0.6,
      "curve-style": "bezier",
    },
  },
  { selector: 'edge[classification="correlated"]', style: { "line-style": "dashed", width: 1.6, "line-color": p.accent } },
  { selector: 'edge[classification="hypothesized"]', style: { "line-style": "dotted", "line-dash-pattern": [2, 4], "line-color": p.inkMuted, opacity: 0.7 } },
  { selector: "edge:selected", style: { width: 2.5, "line-color": p.accent } },
  ];
};

export default function GraphView() {
  const [graph, setGraph] = useState<GraphPayload | null>(null);
  const [detail, setDetail] = useState<EdgeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const host = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  useEffect(() => {
    api.graph().then(setGraph).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (!graph || !host.current) return;
    const instance = cytoscape({
      container: host.current,
      elements: graph.elements as never,
      style: buildStyle(),
      layout: { name: "cose", animate: false, padding: 40, nodeRepulsion: () => 12000 },
      wheelSensitivity: 0.2,
    });
    instance.on("tap", "edge", (event) => {
      const edge = event.target as EdgeSingular;
      api.edge(edge.id()).then(setDetail).catch((e) => setError(String(e)));
    });
    cy.current = instance;
    return () => instance.destroy();
  }, [graph]);

  if (error) return <p className="error">{error}</p>;
  if (!graph) return <p className="muted">Loading graph…</p>;

  const s = graph.stats;

  return (
    <section className="panel">
      <div className="stats">
        <Stat label="nodes" value={s.nodes} />
        <Stat label="observed" value={s.edges_by_classification.observed ?? 0} />
        <Stat label="correlated" value={s.edges_by_classification.correlated ?? 0} />
        <Stat label="hypothesized" value={s.edges_by_classification.hypothesized ?? 0} />
      </div>

      <div className="legend">
        {Object.entries(graph.legend).map(([cls, meaning]) => (
          <div key={cls} className="legend-row">
            <span className={`glyph ${cls}`} aria-hidden />
            <span><strong>{cls}</strong> {meaning}</span>
          </div>
        ))}
      </div>

      <div className="split">
        <div className="canvas" ref={host} />
        <aside className="inspector">
          {!detail && <p className="muted">Select an edge to see the evidence behind it.</p>}
          {detail && <EdgeInspector detail={detail} />}
        </aside>
      </div>

      {graph.caveats.length > 0 && (
        <div className="caveats">
          <h3>Standing caveats</h3>
          <ul className="notes">
            {graph.caveats.map((c) => <li key={c}>{c}</li>)}
          </ul>
        </div>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat">
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function EdgeInspector({ detail }: { detail: EdgeDetail }) {
  return (
    <div className="edge-detail">
      <p className="edge-title">
        <code>{detail.from}</code>
        <span className="relation">{detail.relation}</span>
        <code>{detail.to}</code>
      </p>
      <dl>
        <dt>Classification</dt>
        <dd><span className={`pill ${detail.classification}`}>{detail.classification}</span></dd>
        <dt>Rule</dt>
        <dd><code>{detail.rule_id}</code></dd>
        <dt>Confidence</dt>
        <dd>{detail.confidence}</dd>
        <dt>Observations</dt>
        <dd>{detail.observations}</dd>
      </dl>

      {detail.caveat && <p className="caveat">{detail.caveat}</p>}

      <h4>Evidence ({detail.evidence.length})</h4>
      <ol className="evidence">
        {detail.evidence.map((ev, i) => (
          <li key={`${ev.source_ref}-${i}`}>
            <p>{ev.detail}</p>
            <p className="meta">
              <code>{ev.kind}</code> · {ev.source_ref} · {new Date(ev.observed_at).toLocaleString()}
            </p>
            {ev.snippet_hash && <p className="meta hash">sha256 {ev.snippet_hash.slice(0, 16)}…</p>}
          </li>
        ))}
      </ol>
    </div>
  );
}

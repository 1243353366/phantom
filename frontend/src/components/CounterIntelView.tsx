import { useEffect, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { palette } from "../lib/theme";

interface CounterReport {
  canaries: number;
  hits: number;
  summary: string;
  distinct_origins?: number;
  distinct_clients?: number;
  distinct_networks?: number;
  automated_hits?: number;
  what_they_learned: string[];
  what_you_learned: string[];
  leaked_copies: { label: string; token: string; hits: number; first_seen: string; client_families: string[] }[];
  campaigns: { client_family: string; canaries_touched: string[]; classification: string; caveat: string }[];
  guardrails: Record<string, unknown>;
  caveats?: string[];
}

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
  { selector: 'node[kind="canary"]', style: { shape: "round-rectangle", width: 30, height: 22, "background-color": p.accent, "border-color": p.accent, color: p.ink } },
  { selector: 'node[kind="origin"]', style: { shape: "ellipse" } },
  { selector: 'node[kind="client"]', style: { shape: "diamond", "background-color": p.accentSoft } },
  { selector: 'node[kind="asn"]', style: { shape: "hexagon", width: 22, height: 22 } },
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
  { selector: 'edge[classification="correlated"]', style: { "line-style": "dashed", "line-color": p.accent } },
  { selector: 'edge[classification="hypothesized"]', style: { "line-style": "dotted", "line-dash-pattern": [2, 4], opacity: 0.7 } },
  ];
};

export default function CounterIntelView() {
  const [report, setReport] = useState<CounterReport | null>(null);
  const [label, setLabel] = useState("");
  const [url, setUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const host = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  const load = async () => {
    const [r, g] = await Promise.all([
      fetch("/api/mirror/report").then((x) => x.json()),
      fetch("/api/mirror/graph").then((x) => x.json()),
    ]);
    setReport(r);
    if (host.current) {
      cy.current?.destroy();
      cy.current = cytoscape({
        container: host.current,
        elements: g.elements as never,
        style: buildStyle(),
        layout: { name: "cose", animate: false, padding: 30, nodeRepulsion: () => 14000 },
        wheelSensitivity: 0.2,
      });
    }
  };

  useEffect(() => {
    load().catch((e) => setError(String(e)));
  }, []);

  const mint = async () => {
    setError(null);
    try {
      const res = await fetch("/api/mirror/canary", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? "refused");
      setUrl(data.url);
      setLabel("");
      await load();
    } catch (e) {
      setError(String((e as Error).message));
    }
  };

  return (
    <section className="panel">
      <p className="notice">
        A canary is a decoy image with an opaque token per copy. When someone fetches
        it, the request reveals more about them than it does about you. Nothing is sent
        back, nothing is exploited, and no retaliation of any kind is possible.
      </p>

      <div className="consent-row">
        <label className="field grow">
          <span>Where is this canary going?</span>
          <input
            value={label}
            placeholder="pitch-deck v3 / acme"
            onChange={(e) => setLabel(e.target.value)}
          />
        </label>
        <button className="primary" onClick={mint} disabled={!label.trim()}>
          Mint canary
        </button>
      </div>
      {url && (
        <p className="ok">
          Embed as a remote image: <code>{url}</code>
        </p>
      )}
      {error && <p className="error">{error}</p>}

      <div className="canvas small" ref={host} />

      {report && (
        <>
          <p className="muted">{report.summary}</p>

          <div className="asymmetry">
            <div className="card">
              <h4>What the extraction attempt revealed to them</h4>
              <ul className="notes">{report.what_they_learned.map((l) => <li key={l}>{l}</li>)}</ul>
            </div>
            <div className="card">
              <h4>What it revealed to you</h4>
              <ul className="notes">{report.what_you_learned.map((l) => <li key={l}>{l}</li>)}</ul>
            </div>
          </div>

          <h3>Copies that leaked</h3>
          {report.leaked_copies.length === 0 ? (
            <p className="muted">No canary has been touched yet.</p>
          ) : (
            <table className="table">
              <thead>
                <tr><th>Label</th><th>Token</th><th>Hits</th><th>First seen</th><th>Clients</th></tr>
              </thead>
              <tbody>
                {report.leaked_copies.map((row) => (
                  <tr key={row.token}>
                    <td>{row.label}</td>
                    <td><code>{row.token}</code></td>
                    <td>{row.hits}</td>
                    <td className="nowrap">{row.first_seen.slice(0, 10)}</td>
                    <td className="muted small">{row.client_families.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {report.campaigns.length > 0 && (
            <>
              <h3>Clusters <span className="pill hypothesized">hypothesized</span></h3>
              {report.campaigns.map((c) => (
                <div className="card" key={c.client_family}>
                  <p><strong>{c.client_family}</strong> touched {c.canaries_touched.join(", ")}</p>
                  <p className="caveat">{c.caveat}</p>
                </div>
              ))}
            </>
          )}

          <h3>Guardrails in force</h3>
          <table className="table">
            <tbody>
              {Object.entries(report.guardrails).map(([k, v]) => (
                <tr key={k}>
                  <td><code>{k.replaceAll("_", " ")}</code></td>
                  <td className="muted small">{String(v)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {report.caveats && (
            <ul className="notes">
              {report.caveats.map((c) => <li key={c}>{c}</li>)}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

import { useEffect, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { api, BridgeProposal, ShadowReport } from "../lib/api";
import { palette } from "../lib/theme";

const buildStyle = (): cytoscape.StylesheetStyle[] => {
  const p = palette();
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        "font-size": 8,
        "text-valign": "bottom",
        "text-margin-y": 3,
        color: p.inkMuted,
        "background-color": p.surface2,
        "border-width": 1,
        "border-color": p.line,
        width: 14,
        height: 14,
      },
    },
    { selector: 'node[kind="decoy"]', style: { shape: "round-rectangle", width: 24, height: 18, "background-color": p.accent, "border-color": p.accent } },
    { selector: 'node[kind="protected_object"]', style: { shape: "round-rectangle", width: 24, height: 18, "background-color": p.accent, "border-color": p.accent } },
    { selector: 'node[kind="payload"]', style: { shape: "octagon", width: 18, height: 18 } },
    { selector: 'node[layer="surveillance"]', style: { shape: "diamond", "border-style": "dashed", "border-color": p.accent } },
    {
      selector: "edge",
      style: {
        width: 1,
        "line-color": p.lineStrong,
        "target-arrow-color": p.lineStrong,
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.5,
        "curve-style": "bezier",
      },
    },
    { selector: 'edge[classification="correlated"]', style: { "line-style": "dashed", "line-color": p.accent } },
    { selector: 'edge[classification="hypothesized"]', style: { "line-style": "dotted" } },
    { selector: "edge[cross_layer]", style: { width: 2.4, "line-color": p.accent, "line-style": "dashed" } },
  ];
};

export default function ShadowTraceView() {
  const [report, setReport] = useState<ShadowReport | null>(null);
  const [showSurveillance, setShowSurveillance] = useState(false);
  const [openEvidence, setOpenEvidence] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const host = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);

  const load = async (includeSurveillance: boolean) => {
    const [r, g] = await Promise.all([
      api.shadowReport(),
      api.shadowGraph(includeSurveillance),
    ]);
    setReport(r);
    if (host.current) {
      cy.current?.destroy();
      cy.current = cytoscape({
        container: host.current,
        elements: g.elements as never,
        style: buildStyle(),
        layout: { name: "cose", animate: false, padding: 24, nodeRepulsion: () => 16000 },
        wheelSensitivity: 0.2,
      });
    }
  };

  useEffect(() => {
    load(showSurveillance).catch((e) => setError(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showSurveillance]);

  const decide = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await load(showSurveillance);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };

  if (error && !report) return <p className="error">{error}</p>;
  if (!report) return <p className="muted">Reading Layer 3…</p>;

  const g = report.guardrails as Record<string, unknown>;

  return (
    <section className="panel">
      <div className="layer-strip">
        <LayerTile name="1 · surveillance" what="Who is positioned to observe you" />
        <LayerTile name="2 · relationship" what="Who you actually talk to, locally only" />
        <LayerTile name="3 · adversarial" what="What touched your decoys and locks" active />
      </div>

      {report.refusal_note && <blockquote className="doctrine">{report.refusal_note}</blockquote>}

      <div className="stats">
        <Stat label="events" value={report.events} />
        <Stat label="objects touched" value={report.protected_objects_touched.length} />
        <Stat label="recurring indicators" value={report.recurring_indicators.length} />
        <Stat label="automatic merges" value={String(g.automatic_layer_merges)} />
      </div>

      <div className={report.vault.ok ? "verdict clean" : "verdict dirty"}>
        <p className="verdict-line">
          Evidence vault {report.vault.ok ? "intact" : "BROKEN"} · {report.vault.checked} record(s)
        </p>
        <p className="muted small">{report.vault.reason}</p>
      </div>

      <div className="split">
        <div>
          <label className="check">
            <input
              type="checkbox"
              checked={showSurveillance}
              onChange={(e) => setShowSurveillance(e.target.checked)}
            />
            Show the surveillance layer, through confirmed bridges only
          </label>
          <div className="canvas small" ref={host} />
          <p className="muted small">
            Dashed diamond nodes are surveillance entities that a human chose to
            join. They never appear here on their own.
          </p>
        </div>
        <aside className="inspector">
          <h4>What this layer cannot tell you</h4>
          <ul className="notes">
            {report.cannot_tell_you.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </aside>
      </div>

      <h3>Bridge proposals</h3>
      <p className="notice">{report.bridges.note}</p>
      {report.bridges.pending.length === 0 && (
        <p className="muted">
          Nothing pending. A bridge is only ever proposed deliberately, never
          generated while ingesting.
        </p>
      )}
      {report.bridges.pending.map((proposal) => (
        <BridgeRow
          key={proposal.id}
          proposal={proposal}
          busy={busy}
          onConfirm={() => decide(() => api.confirmBridge(proposal.id, "reviewed in the UI"))}
          onReject={() => decide(() => api.rejectBridge(proposal.id, "evidence did not support it"))}
        />
      ))}
      {report.bridges.confirmed.map((proposal) => (
        <div className="card" key={proposal.id}>
          <p>
            <code>{proposal.surveillance_key}</code> ↔ <code>{proposal.adversarial_key}</code>{" "}
            <span className="pill hypothesized">confirmed by a human</span>
          </p>
          <p className="muted small">{proposal.rationale}</p>
        </div>
      ))}

      <h3>Recurring indicators</h3>
      {report.recurring_indicators.length === 0 ? (
        <p className="muted">Nothing has recurred yet.</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Indicator</th>
              <th>Events</th>
              <th>Objects</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {report.recurring_indicators.map((row) => (
              <tr key={`${row.indicator_type}-${row.indicator}`}>
                <td>{row.indicator_type}</td>
                <td><code>{row.indicator}</code></td>
                <td>{row.events}</td>
                <td>{row.distinct_subjects}</td>
                <td className="nowrap muted small">{row.last_seen.slice(0, 16)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {report.recurring_indicators[0] && (
        <p className="caveat">{report.recurring_indicators[0].caveat}</p>
      )}

      {report.co_occurrence_candidates.length > 0 && (
        <>
          <h3>
            Temporal proximity <span className="pill hypothesized">hypothesized</span>
          </h3>
          {report.co_occurrence_candidates.slice(0, 5).map((c) => (
            <div className="card" key={`${c.indicator}-${c.subjects.join("-")}`}>
              <p>
                {c.subjects.join("  ·  ")}{" "}
                <span className="muted small">
                  {c.gap_minutes} min apart via <code>{c.indicator}</code>, confidence {c.confidence}
                </span>
              </p>
              <p className="caveat">{c.caveat}</p>
            </div>
          ))}
        </>
      )}

      <h3>Events</h3>
      <table className="table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Object</th>
            <th>Outcome</th>
            <th>Observable</th>
            <th>When</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {report.protected_objects_touched.map((row) => (
            <tr key={row.subject}>
              <td className="muted small">{row.kinds.join(", ")}</td>
              <td><code>{row.subject}</code></td>
              <td>
                {row.outcomes.map((o) => (
                  <span className={`pill ${o === "denied" ? "unknown" : "observed"}`} key={o}>
                    {o}
                  </span>
                ))}
              </td>
              <td className="muted small">{row.events} event(s)</td>
              <td className="nowrap muted small">{row.first_at.slice(0, 16)}</td>
              <td>
                <button
                  className="linkish"
                  onClick={() => setOpenEvidence(openEvidence === row.subject ? null : row.subject)}
                >
                  {openEvidence === row.subject ? "hide" : "why else?"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {report.quarantined_payloads.length > 0 && (
        <>
          <h3>Quarantined payloads</h3>
          <table className="table">
            <tbody>
              {report.quarantined_payloads.map((p) => (
                <tr key={p.digest}>
                  <td><code>{p.digest.slice(0, 16)}</code></td>
                  <td className="muted small">
                    {p.size_bytes} bytes · declared {p.declared_type || "nothing"} · sniffed{" "}
                    {p.sniffed_type}
                    {p.executable_signature ? " · executable signature" : ""} · not executed
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h3>Guardrails in force</h3>
      <table className="table">
        <tbody>
          {Object.entries(g)
            .filter(([key]) => key !== "why")
            .map(([key, value]) => (
              <tr key={key}>
                <td><code>{key.replaceAll("_", " ")}</code></td>
                <td className="muted small">{String(value)}</td>
              </tr>
            ))}
        </tbody>
      </table>
      <p className="caveat">{String(g.why)}</p>

      {error && <p className="error">{error}</p>}
      {openEvidence && (
        <p className="muted small">
          Innocent readings are attached to every stored event; open one in the events
          endpoint to read them.
        </p>
      )}
    </section>
  );
}

function LayerTile({ name, what, active }: { name: string; what: string; active?: boolean }) {
  return (
    <div className={active ? "layer-tile active" : "layer-tile"}>
      <span className="layer-name">{name}</span>
      <span className="muted small">{what}</span>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="stat">
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}

function BridgeRow({
  proposal,
  busy,
  onConfirm,
  onReject,
}: {
  proposal: BridgeProposal;
  busy: boolean;
  onConfirm: () => void;
  onReject: () => void;
}) {
  return (
    <div className="card bridge">
      <p>
        <code>{proposal.surveillance_key}</code> ↔ <code>{proposal.adversarial_key}</code>
      </p>
      <p className="muted small">{proposal.rationale}</p>
      <p className="caveat">
        Joining these layers is a judgement call. The same CDN, mail vendor or cloud
        region serves unrelated parties, and a scanner that fetched a decoy is often
        not the sender. Confirm only if the stated observable holds up.
      </p>
      <div className="actions">
        <button className="primary" onClick={onConfirm} disabled={busy}>
          Confirm bridge
        </button>
        <button onClick={onReject} disabled={busy}>
          Reject
        </button>
      </div>
    </div>
  );
}

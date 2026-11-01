import { useEffect, useState } from "react";
import { api, NegativeSpaceReport } from "../lib/api";

export default function NegativeSpaceView() {
  const [report, setReport] = useState<NegativeSpaceReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.negativeSpace().then(setReport).catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!report) return <p className="muted">Reading the gaps…</p>;

  return (
    <section className="panel">
      <blockquote className="doctrine">{report.interpretation}</blockquote>

      <div className="stats">
        <div className="stat">
          <span className="stat-value">{report.total}</span>
          <span className="stat-label">recorded changes</span>
        </div>
        {Object.entries(report.by_change).map(([change, count]) => (
          <div className="stat" key={change}>
            <span className="stat-value">{count}</span>
            <span className="stat-label">{change.replaceAll("_", " ")}</span>
          </div>
        ))}
      </div>

      {report.events.length === 0 ? (
        <p className="muted">
          Nothing has changed yet. A sender needs at least two messages before
          anything can be said about what stopped appearing.
        </p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Change</th>
              <th>Node</th>
              <th>Subject</th>
              <th>Window</th>
              <th>Cause</th>
            </tr>
          </thead>
          <tbody>
            {report.events.map((ev, i) => (
              <tr key={`${ev.node}-${ev.change}-${i}`}>
                <td><span className="pill change">{ev.change.replaceAll("_", " ")}</span></td>
                <td><code>{ev.node}</code></td>
                <td><code>{ev.subject}</code></td>
                <td className="nowrap">
                  {ev.window_from.slice(0, 10)} → {ev.window_to.slice(0, 10)}
                </td>
                <td><span className="pill unknown">unknown</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

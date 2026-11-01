import { useEffect, useState } from "react";
import { api, SelfAuditReport } from "../lib/api";

export default function SelfAuditView() {
  const [report, setReport] = useState<SelfAuditReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.selfAudit().then(setReport).catch((e) => setError(String(e)));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!report) return <p className="muted">Auditing this machine…</p>;

  const clean = report.unmediated_egress_found === 0;

  return (
    <section className="panel">
      <div className={clean ? "verdict clean" : "verdict dirty"}>
        <p className="verdict-line">{report.verdict}</p>
        <p className="muted small">
          {report.observed_egress.total_calls} outbound call(s) logged,{" "}
          {report.observed_egress.blocked_attempts} blocked before sending anything.
        </p>
      </div>

      <h3>Declared outbound destinations</h3>
      <table className="table">
        <thead>
          <tr>
            <th>Host</th>
            <th>Why</th>
            <th>Data sent</th>
          </tr>
        </thead>
        <tbody>
          {report.declarations.map((row) => (
            <tr key={row.host}>
              <td><code>{row.host}</code></td>
              <td>{row.purpose}</td>
              <td className="muted small">{row.data_sent}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {report.findings.filter((f) => f.kind === "unmediated_egress").length > 0 && (
        <>
          <h3>Unmediated paths</h3>
          <ul className="notes">
            {report.findings
              .filter((f) => f.kind === "unmediated_egress")
              .map((f) => (
                <li key={`${f.file}-${f.detail}`}>
                  <code>{f.file}</code> — {f.detail}
                </li>
              ))}
          </ul>
        </>
      )}

      <p className="notice">
        This report is generated from the source tree and the egress log, not from
        assurances. A privacy tool that quietly adds a surveillance layer would defeat
        its own purpose.
      </p>
    </section>
  );
}

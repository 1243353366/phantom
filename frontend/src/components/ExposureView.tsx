import { useState } from "react";
import { api, ExposureResult } from "../lib/api";

const SAMPLE = `name,email,phone
Someone,billing@acme-store.com,
Someone Else,orders@northwind-supply.com,
`;
const CATEGORIES = ["email-analytics", "esp", "adtech", "identity"];

export default function ExposureView() {
  const [csv, setCsv] = useState(SAMPLE);
  const [domains, setDomains] = useState("");
  const [categories, setCategories] = useState<string[]>([]);
  const [result, setResult] = useState<ExposureResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const exclude = domains.split(",").map((d) => d.trim()).filter(Boolean);
      setResult(await api.exposure(csv, exclude, categories));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <p className="notice">
        Paste a CSV you exported yourself. Names, addresses and phone numbers are
        discarded before matching; only domains are compared, and nothing leaves
        this machine.
      </p>

      <div className="split">
        <div>
          <label className="field">
            <span>Contacts CSV</span>
            <textarea rows={8} value={csv} onChange={(e) => setCsv(e.target.value)} />
          </label>

          <label className="field">
            <span>Exclude domains (comma separated)</span>
            <input
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              placeholder="mybank.com, myemployer.com"
            />
          </label>

          <fieldset className="field">
            <legend>Exclude categories</legend>
            {CATEGORIES.map((c) => (
              <label className="check" key={c}>
                <input
                  type="checkbox"
                  checked={categories.includes(c)}
                  onChange={(e) =>
                    setCategories((prev) =>
                      e.target.checked ? [...prev, c] : prev.filter((x) => x !== c),
                    )
                  }
                />
                {c}
              </label>
            ))}
          </fieldset>

          <button className="primary" onClick={run} disabled={busy}>
            {busy ? "Analysing locally…" : "Analyse locally"}
          </button>
          {error && <p className="error">{error}</p>}
        </div>

        <aside>
          {!result && <p className="muted">Results appear here.</p>}
          {result && (
            <>
              <p className="muted">
                {result.contacts_scanned} contacts, {result.distinct_contact_domains} distinct
                domains, {result.intersections.length} intersection(s).
              </p>
              {result.intersections.map((row) => (
                <div className="card" key={row.domain_token}>
                  <p>
                    <code>{row.domain}</code>
                    {row.provider && <span className="pill provider">{row.provider}</span>}
                  </p>
                  <p className="muted small">{row.why}</p>
                  <p className="caveat">{row.confidence_note}</p>
                </div>
              ))}
              <ul className="notes">
                {result.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </>
          )}
        </aside>
      </div>
    </section>
  );
}

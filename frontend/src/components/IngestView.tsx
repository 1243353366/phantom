import { useState } from "react";
import { api } from "../lib/api";

export default function IngestView() {
  const [raw, setRaw] = useState("");
  const [ref, setRef] = useState("manual:1");
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await api.ingest(raw, ref);
      setResult(
        `${res.ingested.sender_domain}: ${res.ingested.pixels} pixel(s), ` +
          `${res.ingested.redirectors} redirector(s), ` +
          `providers ${res.ingested.providers.join(", ") || "none attributed"}, ` +
          `dmarc ${res.ingested.dmarc}`,
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel">
      <p className="notice">
        Paste a raw message (.eml contents). Only headers, URLs and structural HTML
        signals are used; the body is parsed in memory and not retained.
      </p>
      <label className="field">
        <span>Raw message</span>
        <textarea rows={12} value={raw} onChange={(e) => setRaw(e.target.value)}
                  placeholder="From: ...\nReceived: ...\n\n<html>…</html>" />
      </label>
      <label className="field">
        <span>Your label for this message</span>
        <input value={ref} onChange={(e) => setRef(e.target.value)} />
      </label>
      <button className="primary" onClick={submit} disabled={busy || !raw.trim()}>
        {busy ? "Parsing…" : "Ingest"}
      </button>
      {result && <p className="ok">{result}</p>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

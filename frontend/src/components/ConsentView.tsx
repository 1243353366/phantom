import { useState } from "react";
import { api } from "../lib/api";

interface Receipt {
  id: string;
  receipt_hash: string;
  channels_authorised: string[];
  stored_fields: string[];
  not_stored: string[];
  purpose: string;
  policy_version: string;
  how_to_revoke: string;
}

const FIELDS = [
  { key: "gmail_address", flag: "consent_gmail", label: "Gmail address", hint: "email replies", placeholder: "you@gmail.com" },
  { key: "phone_number", flag: "consent_phone", label: "Phone number", hint: "SMS, E.164 only", placeholder: "+15551234567" },
  { key: "work_email", flag: "consent_work_email", label: "Work email", hint: "email replies", placeholder: "you@company.com" },
] as const;

export default function ConsentView() {
  const [values, setValues] = useState<Record<string, string>>({});
  const [flags, setFlags] = useState<Record<string, boolean>>({});
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    try {
      setReceipt(await api.enroll({ ...values, ...flags }));
    } catch (e) {
      setReceipt(null);
      setError(String((e as Error).message));
    }
  };

  const revoke = async () => {
    if (!receipt) return;
    await api.revoke(receipt.id);
    setReceipt({ ...receipt, channels_authorised: [], stored_fields: [], not_stored: [] });
    setValues({});
    setFlags({});
  };

  return (
    <section className="panel">
      <p className="notice">
        Three separate decisions. Each field needs its own opt-in; supplying a value is
        not consent. Values are encrypted with a key that exists only on this machine,
        and revocation clears them immediately.
      </p>

      {FIELDS.map((field) => (
        <div className="consent-row" key={field.key}>
          <label className="field grow">
            <span>{field.label} <em className="muted">({field.hint})</em></span>
            <input
              value={values[field.key] ?? ""}
              placeholder={field.placeholder}
              onChange={(e) => setValues((v) => ({ ...v, [field.key]: e.target.value }))}
            />
          </label>
          <label className="check opt-in">
            <input
              type="checkbox"
              checked={flags[field.flag] ?? false}
              onChange={(e) => setFlags((f) => ({ ...f, [field.flag]: e.target.checked }))}
            />
            I agree to be contacted this way
          </label>
        </div>
      ))}

      <div className="actions">
        <button className="primary" onClick={submit}>Record permission</button>
        {receipt && <button onClick={revoke}>Revoke everything</button>}
      </div>

      {error && <p className="error">{error}</p>}

      {receipt && (
        <div className="card">
          <p><strong>Stored:</strong> {receipt.stored_fields.join(", ") || "nothing"}</p>
          <p><strong>Not stored:</strong> {receipt.not_stored.join(", ") || "nothing"}</p>
          <p><strong>Channels:</strong> {receipt.channels_authorised.join(", ") || "none"}</p>
          <p><strong>Purpose:</strong> {receipt.purpose}</p>
          <p className="muted small">
            Policy {receipt.policy_version} · receipt {receipt.receipt_hash.slice(0, 24)}…
          </p>
        </div>
      )}
    </section>
  );
}

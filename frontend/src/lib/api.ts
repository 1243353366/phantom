/** Thin client. Every call is to the local API; there is no remote endpoint. */

export type Classification = "observed" | "correlated" | "hypothesized";

export interface GraphNodeData {
  id: string;
  label: string;
  kind: string;
  degree: number;
  centrality: number;
  category?: string;
  role?: string;
  parent?: string;
  domain?: string;
  registry_source?: string;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  relation: string;
  classification: Classification;
  rule_id: string;
  confidence: number;
  observations: number;
  evidence_count: number;
  caveat: string | null;
}

export interface GraphPayload {
  elements: { data: GraphNodeData | GraphEdgeData }[];
  stats: {
    nodes: number;
    edges: number;
    edges_by_classification: Record<Classification, number>;
    nodes_by_kind: Record<string, number>;
    density: number;
    top_connectors: { key: string; label: string; degree: number }[];
  };
  legend: Record<Classification, string>;
  caveats: string[];
}

export interface EvidenceRow {
  kind: string;
  detail: string;
  source_ref: string;
  snippet_hash: string | null;
  observed_at: string;
  payload: Record<string, unknown>;
}

export interface EdgeDetail {
  id: string;
  from: string;
  to: string;
  relation: string;
  classification: Classification;
  rule_id: string;
  confidence: number;
  observations: number;
  caveat: string | null;
  evidence: EvidenceRow[];
}

export interface NegativeSpaceEvent {
  subject: string;
  node: string;
  change: string;
  window_from: string;
  window_to: string;
  before: string | null;
  after: string | null;
  cause_unknown: boolean;
  note: string;
}

export interface NegativeSpaceReport {
  total: number;
  by_change: Record<string, number>;
  events: NegativeSpaceEvent[];
  interpretation: string;
}

export interface SelfAuditReport {
  declared_outbound_hosts: string[];
  declarations: { host: string; purpose: string; data_sent: string; data_received: string }[];
  unmediated_egress_found: number;
  findings: { severity: string; kind: string; file: string; detail: string }[];
  observed_egress: { total_calls: number; blocked_attempts: number; hosts: Record<string, unknown> };
  verdict: string;
}

export interface ExposureResult {
  contacts_scanned: number;
  distinct_contact_domains: number;
  intersections: {
    domain_token: string;
    domain: string;
    why: string;
    provider: string | null;
    category: string | null;
    relation: string;
    interpretation: string;
    confidence_note: string;
  }[];
  excluded: Record<string, number>;
  notes: string[];
  relation_kinds: Record<string, string>;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.detail ?? "request refused");
  return data as T;
}

export const api = {
  graph: () => get<GraphPayload>("/api/graph"),
  edge: (id: string) => get<EdgeDetail>(`/api/graph/edge/${id}`),
  negativeSpace: () => get<NegativeSpaceReport>("/api/negative-space"),
  scanNegativeSpace: () => post<{ new_events: number; report: NegativeSpaceReport }>("/api/negative-space/scan", {}),
  selfAudit: () => get<SelfAuditReport>("/api/selfaudit"),
  exposure: (contacts_csv: string, exclude_domains: string[], exclude_categories: string[]) =>
    post<ExposureResult>("/api/exposure/scan", { contacts_csv, exclude_domains, exclude_categories }),
  enroll: (body: Record<string, unknown>) =>
    post<{ id: string; receipt_hash: string; channels_authorised: string[]; stored_fields: string[]; not_stored: string[]; purpose: string; policy_version: string; how_to_revoke: string }>(
      "/api/consent/enroll",
      body,
    ),
  revoke: (id: string) => post<{ revoked_at: string }>(`/api/consent/${id}/revoke`, {}),
  ingest: (raw_email: string, source_ref: string) =>
    post<{ ingested: { sender_domain: string; pixels: number; redirectors: number; providers: string[]; dmarc: string } }>(
      "/api/ingest/eml",
      { raw_email, source_ref },
    ),
};

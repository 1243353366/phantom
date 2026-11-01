/** Thin client. Every call is to the local API; there is no remote endpoint. */

export type Classification = "observed" | "correlated" | "hypothesized";

export type Layer = "surveillance" | "relationship" | "adversarial";

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
  layer?: Layer;
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
  cross_layer?: boolean;
}

export interface GraphPayload {
  elements: { data: GraphNodeData | GraphEdgeData }[];
  stats: {
    nodes: number;
    edges: number;
    edges_by_classification: Record<Classification, number>;
    nodes_by_kind: Record<string, number>;
    nodes_by_layer?: Partial<Record<Layer, number>>;
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

export interface ShadowEventRow {
  event_hash: string;
  kind: string;
  outcome: string;
  subject_ref: string;
  occurred_at: string;
  origin: string;
  client_family: string;
  client_tool: string;
  asn: number | null;
  detail: string;
  alt_explanations: string[];
  vault_seq: number | null;
  credential_material_refused: boolean;
}

export interface RecurringIndicator {
  indicator_type: string;
  indicator: string;
  events: number;
  distinct_subjects: number;
  subjects: string[];
  kinds: string[];
  outcomes: string[];
  first_seen: string;
  last_seen: string;
  alternative_explanations: string[];
  caveat: string;
}

export interface CoOccurrence {
  indicator: string;
  subjects: string[];
  gap_minutes: number;
  confidence: number;
  classification: Classification;
  caveat: string;
  alternative_explanations: string[];
}

export interface BridgeProposal {
  id: string;
  surveillance_key: string;
  adversarial_key: string;
  rationale: string;
  evidence_refs: string[];
  status: string;
  proposed_at: string;
  decided_by: string;
  decided_note: string;
  edge_id: string | null;
}

export interface ShadowReport {
  layer: Layer;
  events: number;
  by_kind: Record<string, number>;
  by_outcome: Record<string, number>;
  protected_objects_touched: {
    subject: string;
    events: number;
    kinds: string[];
    outcomes: string[];
    first_at: string;
  }[];
  recurring_indicators: RecurringIndicator[];
  co_occurrence_candidates: CoOccurrence[];
  quarantined_payloads: {
    digest: string;
    size_bytes: number;
    declared_type: string;
    sniffed_type: string;
    executable_signature: boolean;
    source_ref: string;
  }[];
  bridges: {
    pending: BridgeProposal[];
    confirmed: BridgeProposal[];
    rejected: BridgeProposal[];
    note: string;
  };
  vault: { ok: boolean; checked: number; head: string; reason: string };
  refusal_note: string | null;
  guardrails: Record<string, unknown>;
  cannot_tell_you: string[];
  layers: Record<string, string>;
  rule_catalogue?: {
    id: string;
    classification: Classification;
    relation: string;
    description: string;
    caveat: string | null;
    requires_human_confirmation: boolean;
  }[];
}

export interface ShadowGraphPayload {
  elements: { data: Record<string, unknown> }[];
  stats: GraphPayload["stats"];
  confirmed_bridges: {
    edge_id: string;
    from: string;
    to: string;
    confidence: number;
    caveat: string | null;
    endpoints_visible: boolean;
  }[];
  bridges_drawn: string[];
  legend: Record<string, string>;
  separation: { automatic_merges: number; rule: string; cross_layer_rule: string[] };
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
  shadowReport: () => get<ShadowReport>("/api/shadow/report"),
  shadowEvents: (limit = 200) => get<{ events: ShadowEventRow[] }>(`/api/shadow/events?limit=${limit}`),
  shadowGraph: (includeSurveillance = false) =>
    get<ShadowGraphPayload>(`/api/shadow/graph?include_surveillance=${includeSurveillance}`),
  shadowIndicators: () =>
    get<{ indicators: RecurringIndicator[]; co_occurrences: CoOccurrence[] }>("/api/shadow/indicators"),
  proposeBridge: (body: { surveillance_key: string; adversarial_key: string; rationale: string }) =>
    post<BridgeProposal>("/api/shadow/bridges", body),
  confirmBridge: (id: string, note = "") =>
    post<{ status: string; edge_id: string; confidence: number; caveat: string }>(
      `/api/shadow/bridges/${id}/confirm`,
      { by: "owner", note },
    ),
  rejectBridge: (id: string, note = "") =>
    post<{ status: string }>(`/api/shadow/bridges/${id}/reject`, { by: "owner", note }),
  ingest: (raw_email: string, source_ref: string) =>
    post<{ ingested: { sender_domain: string; pixels: number; redirectors: number; providers: string[]; dmarc: string } }>(
      "/api/ingest/eml",
      { raw_email, source_ref },
    ),
};

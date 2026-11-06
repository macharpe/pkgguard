/** The API contract. Type-only: imported by the handlers and by the dashboard, so the two cannot drift. */

export type Ecosystem = "npm" | "pypi";
export type DetectionVerdict = "blocked" | "flagged" | "allowed" | "error";

export interface DetectionRow {
  id: number;
  ts: string;
  ecosystem: Ecosystem;
  package_name: string;
  version: string | null;
  purl: string | null;
  verdict: DetectionVerdict;
  reason: string | null;
  osv_ids: string | null;
  user_email: string | null;
  src_ip: string | null;
  source: string | null;
}

export interface DetectionsResponse {
  items: DetectionRow[];
  nextBefore: number | null;
}

export interface RefreshRun {
  id: string;
  kind: string;
  trigger: string;
  status: string;
  phase: string | null;
  items_done: number;
  items_total: number;
  added: number;
  updated: number;
  removed: number;
  errors: number;
  started_at: string;
  finished_at: string | null;
}

export interface StatusResponse {
  generatedAt: string;
  ecosystems: Array<{ ecosystem: Ecosystem; last_modified: string; record_count: number; last_synced_at: string }>;
  /** ecosystem -> kind ('malware' | 'vulnerability') -> count */
  advisories: Record<string, Record<string, number>>;
  detections: { total: number; last24h: Record<DetectionVerdict, number> };
  lastRefresh: RefreshRun | null;
}

export interface AdvisoryRow {
  ecosystem: Ecosystem;
  package_name: string;
  osv_id: string;
  kind: "malware" | "vulnerability";
  severity: string | null;
  summary: string | null;
}

export interface OsvSimulation {
  version: string;
  outcome: "blocked" | "flagged" | "allowed" | "error";
  reason: "osv-malware" | "osv-cve" | "lookup-error" | null;
  osvIds: string[];
}

export interface PackageResult {
  ecosystem: Ecosystem;
  name: string;
  malware: AdvisoryRow[];
  vulnerabilities: AdvisoryRow[];
  osv?: OsvSimulation;
}

export interface AdvisoriesResponse {
  items: PackageResult[];
  truncated: boolean;
}

export type ActorInfo = { kind: "user"; email: string } | { kind: "service-token"; clientId: string };

export interface WhoamiResponse {
  actor: ActorInfo;
  label: string;
}

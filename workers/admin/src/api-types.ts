/** The API contract. Type-only: imported by the handlers and by the dashboard, so the two cannot drift. */

import type { Ecosystem } from "@pkgguard/core/ecosystems";

export type { Ecosystem };
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
  /** Quoted by the developer who was blocked; set only for malware decisions. */
  reference: string | null;
}

export interface DetectionsResponse {
  items: DetectionRow[];
  nextBefore: number | null;
}

export interface RefreshRun {
  id: string;
  kind: "monthly" | "daily" | "manual";
  trigger: string;
  status: "queued" | "running" | "complete" | "failed";
  phase: string | null;
  items_done: number;
  items_total: number;
  added: number;
  updated: number;
  removed: number;
  errors: number;
  error_detail: string | null;
  started_at: string;
  finished_at: string | null;
}

/** A run plus an estimate of the seconds left, null while it cannot be estimated. */
export interface RefreshRunInfo extends RefreshRun {
  etaSeconds: number | null;
}

export interface RefreshHistoryResponse {
  items: RefreshRun[];
}

export interface StartRefreshResponse {
  runId: string;
}

/** What the filter Worker last said about itself. The shape is `EnforcementReport` in core; this copy keeps the dashboard free of core's runtime. */
export interface EnforcementInfo {
  enforce: boolean;
  /** Ecosystems that never block, whatever `enforce` says. */
  observeOnly: Ecosystem[];
  /** ISO 8601. Old when the filter has had no traffic since. */
  reportedAt: string;
}

export interface StatusResponse {
  generatedAt: string;
  ecosystems: Array<{ ecosystem: Ecosystem; last_modified: string; record_count: number; last_synced_at: string }>;
  /** ecosystem -> kind ('malware' | 'vulnerability') -> count */
  advisories: Record<string, Record<string, number>>;
  detections: { total: number; last24h: Record<DetectionVerdict, number> };
  lastRefresh: RefreshRun | null;
  /** Null until the filter has reported since it was deployed. That is not the same as "not enforcing". */
  enforcement: EnforcementInfo | null;
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

export type OverrideMode = "block" | "allow";

export interface OverrideItem {
  ecosystem: Ecosystem;
  package_name: string;
  mode: OverrideMode;
  /** Null covers every version. */
  versions: string[] | null;
  note: string | null;
  created_by: string;
  created_at: string;
}

export interface OverridesResponse {
  items: OverrideItem[];
}

export interface AddOverrideRequest {
  ecosystem: Ecosystem;
  name: string;
  mode: OverrideMode;
  versions?: string[];
  note?: string;
}

export interface AddOverrideResponse {
  created: boolean;
  item: OverrideItem;
}

export interface RemoveOverrideRequest {
  ecosystem: Ecosystem;
  name: string;
  mode: OverrideMode;
}

export interface RemoveOverrideResponse {
  removed: OverrideItem;
}

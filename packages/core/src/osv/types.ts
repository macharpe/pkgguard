export type OsvEventType = "introduced" | "fixed" | "last_affected" | "limit";

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvRange {
  type: "SEMVER" | "ECOSYSTEM" | "GIT";
  events: OsvEvent[];
}

/** An OSV `severity[]` entry, e.g. `{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/..." }`. Untrusted: validated before use. */
export interface OsvSeverity {
  type?: string;
  score?: string;
}

export interface OsvAffected {
  package?: { ecosystem: string; name: string; purl?: string };
  severity?: OsvSeverity[];
  ranges?: OsvRange[];
  versions?: string[];
  database_specific?: { cwes?: Array<{ cweId?: string }> } & Record<string, unknown>;
}

export interface OsvRecord {
  id: string;
  aliases?: string[];
  summary?: string;
  modified: string;
  withdrawn?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  database_specific?: { cwe_ids?: string[]; severity?: string } & Record<string, unknown>;
}

export type AdvisoryKind = "malware" | "vulnerability";

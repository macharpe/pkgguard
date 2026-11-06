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

export interface OsvAffected {
  package?: { ecosystem: string; name: string; purl?: string };
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
  affected?: OsvAffected[];
  database_specific?: { cwe_ids?: string[]; severity?: string } & Record<string, unknown>;
}

export type AdvisoryKind = "malware" | "vulnerability";

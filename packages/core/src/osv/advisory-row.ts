import { isEcosystem, type Ecosystem } from "../ecosystem-ids.js";
import type { Advisory } from "./distill.js";
import type { AffectedSpec } from "./match.js";

/** The `advisories` table's columns, in the order `advisoryRow` returns values. */
export const ADVISORY_COLUMNS = [
  "ecosystem",
  "osv_id",
  "package_name",
  "namespace",
  "kind",
  "cwe_ids",
  "severity",
  "summary",
  "ranges_json",
  "withdrawn",
  "modified",
] as const;

export type RowValue = string | number | null;

const SUMMARY_MAX = 500;
/** D1's SQL importer rejects NUL, so it never reaches the table, however the row is written. */
const clean = (value: string): string => value.replaceAll("\u0000", "");
const cleanOrNull = (value: string | null): string | null => (value === null ? null : clean(value));

/**
 * The single definition of how an Advisory becomes a table row. The offline bootstrap (SQL text)
 * and the refresh Workflow (bound parameters) both use it, so they cannot drift apart.
 */
export function advisoryRow(a: Advisory): RowValue[] {
  return [
    a.ecosystem,
    clean(a.osvId),
    clean(a.packageName),
    cleanOrNull(a.namespace),
    a.kind,
    a.cweIds.length > 0 ? clean(a.cweIds.join(",")) : null,
    a.severity,
    a.summary === null ? null : clean(a.summary.slice(0, SUMMARY_MAX)),
    clean(JSON.stringify(a.spec)),
    a.withdrawn ? 1 : 0,
    a.modified,
  ];
}

const isSpec = (value: unknown): value is AffectedSpec =>
  typeof value === "object" && value !== null && Array.isArray((value as AffectedSpec).r) && Array.isArray((value as AffectedSpec).v);

/** The inverse, for rebuilding KV entries from D1. Returns null for a row that cannot be trusted, so one bad row never aborts a rebuild. */
export function advisoryFromRow(row: Record<string, unknown>): Advisory | null {
  const { ecosystem, osv_id, package_name, namespace, kind, cwe_ids, severity, summary, ranges_json, withdrawn, modified } = row;
  if (!isEcosystem(ecosystem)) return null;
  if (typeof osv_id !== "string" || typeof package_name !== "string" || typeof modified !== "string") return null;
  if (kind !== "malware" && kind !== "vulnerability") return null;
  if (typeof ranges_json !== "string") return null;
  let spec: unknown;
  try {
    spec = JSON.parse(ranges_json);
  } catch {
    return null;
  }
  if (!isSpec(spec)) return null;
  return {
    ecosystem,
    osvId: osv_id,
    packageName: package_name,
    namespace: typeof namespace === "string" ? namespace : null,
    kind,
    severity: typeof severity === "string" ? severity : null,
    summary: typeof summary === "string" ? summary : null,
    cweIds: typeof cwe_ids === "string" && cwe_ids !== "" ? cwe_ids.split(",") : [],
    spec,
    withdrawn: withdrawn === 1 || withdrawn === true,
    modified,
  };
}

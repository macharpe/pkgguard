import type { Advisory } from "../../packages/core/src/index.js";

const SUMMARY_MAX = 500;

/** SQLite string literal. Strips NUL, which D1's importer rejects, and doubles single quotes. */
export function sqlString(value: string | null): string {
  if (value === null) return "NULL";
  return `'${value.replaceAll("\u0000", "").replaceAll("'", "''")}'`;
}

export function advisoryInsert(a: Advisory): string {
  const summary = a.summary === null ? null : a.summary.slice(0, SUMMARY_MAX);
  const values = [
    sqlString(a.ecosystem),
    sqlString(a.osvId),
    sqlString(a.packageName),
    sqlString(a.namespace),
    sqlString(a.kind),
    sqlString(a.cweIds.length > 0 ? a.cweIds.join(",") : null),
    sqlString(a.severity),
    sqlString(summary),
    sqlString(JSON.stringify(a.spec)),
    a.withdrawn ? "1" : "0",
    sqlString(a.modified),
  ];
  return (
    "INSERT OR REPLACE INTO advisories " +
    "(ecosystem, osv_id, package_name, namespace, kind, cwe_ids, severity, summary, ranges_json, withdrawn, modified) " +
    `VALUES (${values.join(", ")});`
  );
}

export function syncStateInsert(ecosystem: string, lastModified: string, recordCount: number, syncedAt: string): string {
  return (
    "INSERT OR REPLACE INTO sync_state (ecosystem, last_modified, record_count, last_synced_at) " +
    `VALUES (${sqlString(ecosystem)}, ${sqlString(lastModified)}, ${recordCount}, ${sqlString(syncedAt)});`
  );
}

export function* chunk<T>(items: readonly T[], size: number): Generator<T[]> {
  for (let i = 0; i < items.length; i += size) yield items.slice(i, i + size);
}

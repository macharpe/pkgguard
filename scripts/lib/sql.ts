import { ADVISORY_COLUMNS, advisoryRow, type Advisory } from "../../packages/core/src/index.js";

/** SQLite string literal. Strips NUL, which D1's importer rejects, and doubles single quotes. */
export function sqlString(value: string | null): string {
  if (value === null) return "NULL";
  return `'${value.replaceAll("\u0000", "").replaceAll("'", "''")}'`;
}

export function advisoryInsert(a: Advisory): string {
  const values = advisoryRow(a).map((value) => (typeof value === "number" ? String(value) : sqlString(value)));
  return (
    `INSERT OR REPLACE INTO advisories (${ADVISORY_COLUMNS.join(", ")}) ` + `VALUES (${values.join(", ")});`
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

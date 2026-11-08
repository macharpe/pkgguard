import { ADVISORY_COLUMNS, advisoryFromRow, advisoryRow, buildKvEntry, distill, enabledEcosystemSqlList, kvKey, type Advisory, type Ecosystem, type OsvRecord } from "@pkgguard/core";

/** D1 allows 100 bound parameters per query; stay well inside it. */
const IN_CHUNK = 90;

export interface ApplyDeps {
  db: D1Database;
  kv: KVNamespace;
  now: string;
}

export interface ApplyResult {
  /** Records whose osv_id had no rows before. */
  added: number;
  /** Records that replaced existing rows. */
  updated: number;
  /** Records marked withdrawn by OSV. */
  withdrawn: number;
  packages: number;
  kvWrites: number;
  kvDeletes: number;
  /** Rows in D1 that could not be read back and were left out of the KV entry. */
  unreadableRows: number;
}

const chunks = <T>(items: readonly T[], size: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
};
const marks = (n: number): string => Array.from({ length: n }, () => "?").join(",");
const pkgKey = (ecosystem: string, name: string): string => `${ecosystem}\u0000${name}`;

/**
 * Applies a batch of OSV records: replaces each record's rows in D1 in one atomic batch, then rebuilds the KV
 * entry of every package the batch touched from D1, the source of truth. Idempotent, so a retried step is safe.
 *
 * Each record's old rows are deleted first, so a package a record no longer lists loses its stale advisory.
 * Those old packages are included in the KV rebuild for the same reason.
 */
export async function applyRecords(deps: ApplyDeps, records: readonly OsvRecord[]): Promise<ApplyResult> {
  const result: ApplyResult = { added: 0, updated: 0, withdrawn: 0, packages: 0, kvWrites: 0, kvDeletes: 0, unreadableRows: 0 };
  if (records.length === 0) return result;

  const ids = [...new Set(records.map((r) => r.id))];
  const advisories = new Map<string, Advisory>();
  for (const record of records) {
    if (typeof record.withdrawn === "string") result.withdrawn++;
    for (const a of distill(record)) advisories.set(`${a.ecosystem}|${a.osvId}|${a.packageName}`, a);
  }

  // What the batch replaces: which of these ids already had rows, and which packages they covered.
  const before = new Map<string, Set<string>>();
  const touched = new Map<string, { ecosystem: Ecosystem; name: string }>();
  for (const part of chunks(ids, IN_CHUNK)) {
    const { results } = await deps.db
      .prepare(`SELECT osv_id, ecosystem, package_name FROM advisories WHERE ecosystem IN (${enabledEcosystemSqlList()}) AND osv_id IN (${marks(part.length)})`)
      .bind(...part)
      .all<{ osv_id: string; ecosystem: Ecosystem; package_name: string }>();
    for (const row of results) {
      (before.get(row.osv_id) ?? before.set(row.osv_id, new Set()).get(row.osv_id))?.add(row.package_name);
      touched.set(pkgKey(row.ecosystem, row.package_name), { ecosystem: row.ecosystem, name: row.package_name });
    }
  }
  for (const id of ids) before.has(id) ? result.updated++ : result.added++;
  for (const a of advisories.values()) touched.set(pkgKey(a.ecosystem, a.packageName), { ecosystem: a.ecosystem, name: a.packageName });

  const insert = deps.db.prepare(`INSERT OR REPLACE INTO advisories (${ADVISORY_COLUMNS.join(", ")}) VALUES (${marks(ADVISORY_COLUMNS.length)})`);
  const remove = deps.db.prepare(`DELETE FROM advisories WHERE ecosystem IN (${enabledEcosystemSqlList()}) AND osv_id = ?`);
  await deps.db.batch([...ids.map((id) => remove.bind(id)), ...[...advisories.values()].map((a) => insert.bind(...advisoryRow(a)))]);

  // Rebuild KV from the rows now in D1.
  const byEcosystem = new Map<Ecosystem, string[]>();
  for (const { ecosystem, name } of touched.values()) (byEcosystem.get(ecosystem) ?? byEcosystem.set(ecosystem, []).get(ecosystem))?.push(name);

  for (const [ecosystem, names] of byEcosystem) {
    for (const part of chunks(names, IN_CHUNK)) {
      const { results } = await deps.db
        .prepare(`SELECT ${ADVISORY_COLUMNS.join(", ")} FROM advisories WHERE ecosystem = ? AND package_name IN (${marks(part.length)})`)
        .bind(ecosystem, ...part)
        .all<Record<string, unknown>>();

      const byName = new Map<string, Advisory[]>(part.map((n) => [n, []]));
      for (const row of results) {
        const advisory = advisoryFromRow(row);
        if (advisory === null) result.unreadableRows++;
        else byName.get(advisory.packageName)?.push(advisory);
      }

      for (const [name, list] of byName) {
        const key = kvKey(ecosystem, name);
        if (key === null) continue;
        const entry = buildKvEntry(list, deps.now);
        if (entry === null) {
          await deps.kv.delete(key);
          result.kvDeletes++;
        } else {
          await deps.kv.put(key, JSON.stringify(entry));
          result.kvWrites++;
        }
        result.packages++;
      }
    }
  }
  return result;
}

import { ENABLED_ECOSYSTEMS, type Ecosystem } from "@pkgguard/core";
import { maxIso, normalizeIso } from "./iso.js";
import { scanModifiedCsv } from "./modified-csv.js";
import { OSV_BASE, osvDirectory, type FetchLike } from "./osv-fetch.js";
import { updateRun } from "./runs.js";

/** More than this is not a delta: it is a rebuild, which is the bootstrap's job. */
export const MAX_DELTA = 20_000;
const INSERT_BATCH = 500;

export class PlanError extends Error {}

export interface PlanDeps {
  db: D1Database;
  fetch: FetchLike;
}

interface PlannedItem {
  ecosystem: Ecosystem;
  id: string;
  modified: string;
}

/**
 * Lists what changed since each ecosystem's high-water mark and stores it as the run's work list.
 * Oldest modification first, so partial progress always leaves a usable high-water mark.
 * Re-running for the same run id replaces the list.
 */
export async function planRun(deps: PlanDeps, runId: string): Promise<{ total: number }> {
  const planned: PlannedItem[] = [];
  const recordCounts = new Map<Ecosystem, number>();

  for (const ecosystem of ENABLED_ECOSYSTEMS) {
    const state = await deps.db.prepare("SELECT last_modified FROM sync_state WHERE ecosystem = ?").bind(ecosystem).first<{ last_modified: string }>();
    if (!state) throw new PlanError(`no sync state for ${ecosystem}: run the bootstrap first`);

    const response = await deps.fetch(`${OSV_BASE}/${osvDirectory(ecosystem)}/modified_id.csv`);
    if (!response.ok || !response.body) throw new Error(`modified_id.csv for ${ecosystem} returned HTTP ${response.status}`);
    const scan = await scanModifiedCsv(response.body, state.last_modified, MAX_DELTA - planned.length);
    recordCounts.set(ecosystem, scan.total);
    for (const item of scan.items) planned.push({ ecosystem, id: item.id, modified: item.modified });
  }

  planned.sort((a, b) => (normalizeIso(a.modified) ?? "").localeCompare(normalizeIso(b.modified) ?? ""));

  await deps.db.prepare("DELETE FROM refresh_items WHERE run_id = ?").bind(runId).run();
  const insert = deps.db.prepare("INSERT INTO refresh_items (run_id, seq, ecosystem, osv_id, modified) VALUES (?, ?, ?, ?, ?)");
  for (let i = 0; i < planned.length; i += INSERT_BATCH) {
    await deps.db.batch(planned.slice(i, i + INSERT_BATCH).map((item, j) => insert.bind(runId, i + j, item.ecosystem, item.id, item.modified)));
  }

  // The count of records OSV lists, which is what sync_state.record_count means.
  for (const [ecosystem, total] of recordCounts) {
    await deps.db.prepare("UPDATE sync_state SET record_count = ? WHERE ecosystem = ?").bind(total, ecosystem).run();
  }
  await updateRun(deps.db, runId, { items_total: planned.length, items_done: 0, phase: planned.length === 0 ? "nothing to do" : "fetching records" });
  return { total: planned.length };
}

export interface Finalized {
  highWater: Partial<Record<Ecosystem, string>>;
  failed: number;
}

/**
 * Moves each ecosystem's high-water mark forward, but never past a record that failed: the mark stops
 * just before the oldest failure so the next run fetches it again. Everything from that point is re-fetched, harmlessly.
 */
export async function advanceHighWater(db: D1Database, runId: string, syncedAt: string): Promise<Finalized> {
  const { results } = await db.prepare("SELECT ecosystem, modified, status FROM refresh_items WHERE run_id = ?").bind(runId).all<{ ecosystem: Ecosystem; modified: string; status: string }>();
  const highWater: Partial<Record<Ecosystem, string>> = {};
  let failed = 0;

  for (const ecosystem of ENABLED_ECOSYSTEMS) {
    const items = results.filter((r) => r.ecosystem === ecosystem);
    const failures = items.filter((r) => r.status === "failed");
    failed += failures.length;
    const oldestFailure = failures.map((r) => normalizeIso(r.modified)).filter((v): v is string => v !== null).sort()[0] ?? null;
    const settled = items.filter((r) => r.status === "done" || r.status === "missing").filter((r) => {
      const norm = normalizeIso(r.modified);
      return norm !== null && (oldestFailure === null || norm < oldestFailure);
    });
    const newest = maxIso(settled.map((r) => r.modified));

    const state = await db.prepare("SELECT last_modified FROM sync_state WHERE ecosystem = ?").bind(ecosystem).first<{ last_modified: string }>();
    const previous = state ? normalizeIso(state.last_modified) : null;
    const candidate = newest === null ? null : normalizeIso(newest);
    if (newest !== null && candidate !== null && (previous === null || candidate > previous)) {
      await db.prepare("UPDATE sync_state SET last_modified = ?, last_synced_at = ? WHERE ecosystem = ?").bind(newest, syncedAt, ecosystem).run();
      highWater[ecosystem] = newest;
    } else {
      await db.prepare("UPDATE sync_state SET last_synced_at = ? WHERE ecosystem = ?").bind(syncedAt, ecosystem).run();
    }
  }
  return { highWater, failed };
}

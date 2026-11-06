import type { Ecosystem } from "@pkgguard/core";
import { applyRecords } from "./apply.js";
import { fetchRecords, type FetchLike } from "./osv-fetch.js";

export const BATCH_SIZE = 100;

export interface BatchDeps {
  db: D1Database;
  kv: KVNamespace;
  fetch: FetchLike;
  now: string;
  sleep?: (ms: number) => Promise<void>;
}

export interface BatchResult {
  processed: number;
  ok: number;
  missing: number;
  failed: number;
  added: number;
  updated: number;
  withdrawn: number;
}

/**
 * Fetches and applies items [start, start + BATCH_SIZE) of the run's work list.
 * Item outcomes are written only after the apply succeeds, and the whole step is idempotent, so a retry is safe.
 * A record that cannot be fetched is marked failed and does not stop the batch.
 */
export async function processBatch(deps: BatchDeps, runId: string, start: number): Promise<BatchResult> {
  const { results: items } = await deps.db
    .prepare("SELECT seq, ecosystem, osv_id FROM refresh_items WHERE run_id = ? AND seq >= ? AND seq < ? ORDER BY seq")
    .bind(runId, start, start + BATCH_SIZE)
    .all<{ seq: number; ecosystem: Ecosystem; osv_id: string }>();

  const out: BatchResult = { processed: items.length, ok: 0, missing: 0, failed: 0, added: 0, updated: 0, withdrawn: 0 };
  if (items.length === 0) return out;

  const fetched = await fetchRecords(
    deps.fetch,
    items.map((i) => ({ ecosystem: i.ecosystem, id: i.osv_id })),
    deps.sleep ? { sleep: deps.sleep } : {},
  );

  const records = fetched.flatMap((r) => (r.status === "ok" ? [r.record] : []));
  const applied = await applyRecords({ db: deps.db, kv: deps.kv, now: deps.now }, records);
  out.added = applied.added;
  out.updated = applied.updated;
  out.withdrawn = applied.withdrawn;

  const mark = deps.db.prepare("UPDATE refresh_items SET status = ? WHERE run_id = ? AND seq = ?");
  await deps.db.batch(
    items.map((item, i) => {
      const result = fetched[i];
      const status = result?.status === "ok" ? "done" : (result?.status ?? "failed");
      out[status === "done" ? "ok" : (status as "missing" | "failed")]++;
      return mark.bind(status, runId, item.seq);
    }),
  );
  return out;
}

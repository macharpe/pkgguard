import type { Env } from "../env.js";
import { json } from "../http.js";

const COUNTS_TTL_MS = 5 * 60_000;
let counts: { at: number; value: Record<string, Record<string, number>> } | null = null;

/** Test hook. */
export const resetStatusCache = (): void => {
  counts = null;
};

/** A full-table GROUP BY reads every advisory row, so it is memoised per isolate. */
async function advisoryCounts(db: D1Database, now: number): Promise<Record<string, Record<string, number>>> {
  if (counts && now - counts.at < COUNTS_TTL_MS) return counts.value;
  const { results } = await db
    .prepare("SELECT ecosystem, kind, COUNT(*) AS n FROM advisories WHERE withdrawn = 0 GROUP BY ecosystem, kind")
    .all<{ ecosystem: string; kind: string; n: number }>();
  const value: Record<string, Record<string, number>> = {};
  for (const row of results) (value[row.ecosystem] ??= {})[row.kind] = row.n;
  counts = { at: now, value };
  return value;
}

export async function status(env: Env, now: Date = new Date()): Promise<Response> {
  const since = new Date(now.getTime() - 24 * 3600_000).toISOString();
  const [sync, last24h, total, lastRefresh, advisories] = await Promise.all([
    env.DB.prepare("SELECT ecosystem, last_modified, record_count, last_synced_at FROM sync_state ORDER BY ecosystem").all(),
    env.DB.prepare("SELECT verdict, COUNT(*) AS n FROM detections WHERE ts >= ? GROUP BY verdict").bind(since).all<{ verdict: string; n: number }>(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM detections").first<{ n: number }>(),
    env.DB.prepare(
      "SELECT id, kind, trigger, status, phase, items_done, items_total, added, updated, removed, errors, started_at, finished_at FROM refresh_runs ORDER BY started_at DESC LIMIT 1",
    ).first(),
    advisoryCounts(env.DB, now.getTime()),
  ]);

  const byVerdict: Record<string, number> = { blocked: 0, flagged: 0, allowed: 0, error: 0 };
  for (const row of last24h.results) byVerdict[row.verdict] = row.n;

  return json({
    generatedAt: now.toISOString(),
    ecosystems: sync.results,
    advisories,
    detections: { last24h: byVerdict, total: total?.n ?? 0 },
    lastRefresh: lastRefresh ?? null,
  });
}

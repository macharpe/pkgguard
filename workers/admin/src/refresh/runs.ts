export type RunKind = "monthly" | "daily" | "manual";
export type RunStatus = "queued" | "running" | "complete" | "failed";

export interface RunRow {
  id: string;
  kind: RunKind;
  trigger: string;
  status: RunStatus;
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

/** A run that has been "active" longer than this is presumed dead (a crashed Workflow), so it no longer blocks new runs. */
export const ACTIVE_RUN_MAX_AGE_MS = 3 * 3600_000;

const COLUMNS = "id, kind, trigger, status, phase, items_done, items_total, added, updated, removed, errors, error_detail, started_at, finished_at";

export type StartResult = { started: true } | { started: false; activeId: string };

/** Inserts the run only if none is active, in one statement, so two simultaneous requests cannot both start. */
export async function startRun(db: D1Database, run: { id: string; kind: RunKind; trigger: string }, now: Date): Promise<StartResult> {
  const cutoff = new Date(now.getTime() - ACTIVE_RUN_MAX_AGE_MS).toISOString();
  const result = await db
    .prepare(
      "INSERT INTO refresh_runs (id, kind, trigger, status, phase, started_at) " +
        "SELECT ?, ?, ?, 'queued', 'queued', ? " +
        "WHERE NOT EXISTS (SELECT 1 FROM refresh_runs WHERE status IN ('queued', 'running') AND started_at > ?)",
    )
    .bind(run.id, run.kind, run.trigger, now.toISOString(), cutoff)
    .run();
  if ((result.meta.changes ?? 0) > 0) return { started: true };
  const active = await db
    .prepare("SELECT id FROM refresh_runs WHERE status IN ('queued', 'running') AND started_at > ? ORDER BY started_at DESC LIMIT 1")
    .bind(cutoff)
    .first<{ id: string }>();
  return { started: false, activeId: active?.id ?? "unknown" };
}

/** Only these columns can be written, so a caller can never smuggle a column name into the statement. */
const WRITABLE = ["status", "phase", "items_done", "items_total", "added", "updated", "removed", "errors", "error_detail", "finished_at"] as const;
export type RunPatch = Partial<Pick<RunRow, (typeof WRITABLE)[number]>>;

export async function updateRun(db: D1Database, id: string, patch: RunPatch): Promise<void> {
  const keys = WRITABLE.filter((k) => k in patch);
  if (keys.length === 0) return;
  await db
    .prepare(`UPDATE refresh_runs SET ${keys.map((k) => `${k} = ?`).join(", ")} WHERE id = ?`)
    .bind(...keys.map((k) => patch[k] ?? null), id)
    .run();
}

export const getRun = (db: D1Database, id: string): Promise<RunRow | null> =>
  db.prepare(`SELECT ${COLUMNS} FROM refresh_runs WHERE id = ?`).bind(id).first<RunRow>();

export async function listRuns(db: D1Database, limit: number): Promise<RunRow[]> {
  const { results } = await db.prepare(`SELECT ${COLUMNS} FROM refresh_runs ORDER BY started_at DESC LIMIT ?`).bind(limit).all<RunRow>();
  return results;
}

/** Seconds left at the current rate, or null while it cannot be estimated. */
export function etaSeconds(run: Pick<RunRow, "status" | "items_done" | "items_total" | "started_at">, now: Date): number | null {
  if (run.status !== "running" || run.items_done <= 0 || run.items_total <= run.items_done) return null;
  const elapsed = (now.getTime() - Date.parse(run.started_at)) / 1000;
  if (!Number.isFinite(elapsed) || elapsed <= 0) return null;
  return Math.max(0, Math.round((elapsed / run.items_done) * (run.items_total - run.items_done)));
}

/** Progress is derived from the work list, never accumulated, so a retried step cannot double-count. */
export async function syncProgress(db: D1Database, runId: string, phase: string): Promise<void> {
  await db
    .prepare(
      "UPDATE refresh_runs SET phase = ?, " +
        "items_done = (SELECT COUNT(*) FROM refresh_items WHERE run_id = ? AND status != 'pending'), " +
        "errors = (SELECT COUNT(*) FROM refresh_items WHERE run_id = ? AND status = 'failed') WHERE id = ?",
    )
    .bind(phase, runId, runId, runId)
    .run();
}

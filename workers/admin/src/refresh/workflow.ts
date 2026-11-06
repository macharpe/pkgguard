import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { NonRetryableError } from "cloudflare:workflows";
import type { Env } from "../env.js";
import { BATCH_SIZE, processBatch, type BatchResult } from "./batch.js";
import type { RefreshParams } from "./launch.js";
import { DeltaTooLarge } from "./modified-csv.js";
import { notifyRefresh } from "./notify.js";
import { PlanError, advanceHighWater, planRun } from "./plan.js";
import { syncProgress, updateRun } from "./runs.js";

const PLAN_STEP = { retries: { limit: 3, delay: "10 seconds", backoff: "exponential" }, timeout: "3 minutes" } as const;
const NOTIFY_STEP = { retries: { limit: 1, delay: "5 seconds" }, timeout: "30 seconds" } as const;
const BATCH_STEP = { retries: { limit: 3, delay: "10 seconds", backoff: "exponential" }, timeout: "5 minutes" } as const;
/** Failed runs keep their work list for this long, for diagnosis. */
const KEEP_ITEMS_MS = 7 * 24 * 3600_000;
const DETAIL_MAX = 500;

export interface RunSummary {
  total: number;
  added: number;
  updated: number;
  withdrawn: number;
  failed: number;
}

/** Called through a wrapper: workerd throws "Illegal invocation" if fetch is stored and called as a property. */
const fetchWrapper = (url: string, init?: RequestInit): Promise<Response> => fetch(url, init);

/** Anything that retrying cannot fix must not be retried. */
function rethrow(err: unknown): never {
  if (err instanceof PlanError || err instanceof DeltaTooLarge) throw new NonRetryableError(err.message);
  throw err;
}

/** Orchestration only: every step delegates to a function tested on its own. Kept out of the class so it can be driven directly. */
export async function executeRefresh(env: Pick<Env, "DB" | "PKG_INDEX" | "GCHAT_WEBHOOK" | "PUBLIC_URL">, runId: string, step: Pick<WorkflowStep, "do">): Promise<RunSummary> {
  const { DB: db, PKG_INDEX: kv } = env;

  try {
    await step.do("start", () => updateRun(db, runId, { status: "running", phase: "planning" }));

    const plan = await step.do("plan", PLAN_STEP, async () => {
      try {
        return await planRun({ db, fetch: fetchWrapper }, runId);
      } catch (err) {
        return rethrow(err);
      }
    });

    const totals = { added: 0, updated: 0, withdrawn: 0 };
    for (let start = 0; start < plan.total; start += BATCH_SIZE) {
      const result: BatchResult = await step.do(`records ${start}-${Math.min(start + BATCH_SIZE, plan.total) - 1}`, BATCH_STEP, async () => {
        const batch = await processBatch({ db, kv, fetch: fetchWrapper, now: new Date().toISOString() }, runId, start);
        await syncProgress(db, runId, "applying records");
        return batch;
      });
      totals.added += result.added;
      totals.updated += result.updated;
      totals.withdrawn += result.withdrawn;
    }

    const summary = await step.do("finalize", async () => {
      const now = new Date();
      const { failed } = await advanceHighWater(db, runId, now.toISOString());
      await syncProgress(db, runId, "complete");
      await updateRun(db, runId, {
        status: "complete",
        added: totals.added,
        updated: totals.updated,
        removed: totals.withdrawn,
        finished_at: now.toISOString(),
        error_detail: failed > 0 ? `${failed} records could not be fetched and will be retried on the next run` : null,
      });
      // A clean run needs no work list. A run with failures keeps it, and old lists are pruned either way.
      if (failed === 0) await db.prepare("DELETE FROM refresh_items WHERE run_id = ?").bind(runId).run();
      await db
        .prepare("DELETE FROM refresh_items WHERE run_id IN (SELECT id FROM refresh_runs WHERE started_at < ?)")
        .bind(new Date(now.getTime() - KEEP_ITEMS_MS).toISOString())
        .run();
      return { total: plan.total, ...totals, failed };
    });
    await step.do("notify", NOTIFY_STEP, () => notifyRefresh(env, runId));
    return summary;
  } catch (err) {
    const detail = (err instanceof Error ? err.message : String(err)).slice(0, DETAIL_MAX);
    await step.do("record failure", () => updateRun(db, runId, { status: "failed", phase: "failed", error_detail: detail, finished_at: new Date().toISOString() }));
    // The original error is what matters; a problem telling Chat about it must not replace it.
    await step.do("notify failure", NOTIFY_STEP, () => notifyRefresh(env, runId)).catch(() => undefined);
    throw err;
  }
}

export class RefreshWorkflow extends WorkflowEntrypoint<Env, RefreshParams> {
  override run(event: WorkflowEvent<RefreshParams>, step: WorkflowStep): Promise<RunSummary> {
    return executeRefresh(this.env, event.instanceId, step);
  }
}

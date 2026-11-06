import type { Env } from "../env.js";
import { startRun, updateRun, type RunKind } from "./runs.js";

export interface RefreshParams {
  kind: RunKind;
  trigger: string;
}

export type LaunchResult = { started: true; runId: string } | { started: false; activeId: string };

/**
 * Records the run, then starts the Workflow under the same id. The id is the only link between the two,
 * which is how the dashboard follows progress. If the Workflow cannot be created the run is marked failed
 * so it does not block the next attempt until the stale-run cutoff.
 */
export async function launchRefresh(env: Pick<Env, "DB" | "REFRESH">, params: RefreshParams, now: Date): Promise<LaunchResult> {
  const runId = crypto.randomUUID();
  const started = await startRun(env.DB, { id: runId, kind: params.kind, trigger: params.trigger }, now);
  if (!started.started) return { started: false, activeId: started.activeId };
  try {
    await env.REFRESH.create({ id: runId, params });
  } catch (err) {
    await updateRun(env.DB, runId, { status: "failed", phase: "failed to start", error_detail: "could not start the refresh workflow", finished_at: now.toISOString() });
    throw err;
  }
  return { started: true, runId };
}

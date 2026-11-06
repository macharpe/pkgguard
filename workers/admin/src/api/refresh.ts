import { actorLabel, type Actor } from "../access-jwt.js";
import type { RefreshHistoryResponse, RefreshRunInfo, StartRefreshResponse } from "../api-types.js";
import type { Env } from "../env.js";
import { HttpError, intParam, json } from "../http.js";
import { launchRefresh } from "../refresh/launch.js";
import { etaSeconds, getRun, listRuns, type RunRow } from "../refresh/runs.js";

const RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function startRefresh(env: Env, actor: Actor, now: Date): Promise<Response> {
  const trigger = actorLabel(actor);
  const result = await launchRefresh(env, { kind: "manual", trigger }, now);
  if (!result.started) return json({ error: "a refresh is already running", runId: result.activeId }, 409);
  await env.DB.prepare("INSERT INTO audit_log (ts, actor, action, detail) VALUES (?, ?, 'refresh.start', ?)").bind(now.toISOString(), trigger, result.runId).run();
  const body: StartRefreshResponse = { runId: result.runId };
  return json(body, 202);
}

export async function refreshStatus(env: Env, id: string, now: Date): Promise<Response> {
  if (!RUN_ID.test(id)) throw new HttpError(404, "not found");
  const run: RunRow | null = await getRun(env.DB, id);
  if (run === null) throw new HttpError(404, "not found");
  const body: RefreshRunInfo = { ...run, etaSeconds: etaSeconds(run, now) };
  return json(body);
}

export async function refreshHistory(env: Env, url: URL): Promise<Response> {
  const body: RefreshHistoryResponse = { items: await listRuns(env.DB, intParam(url, "limit", 10, 50)) };
  return json(body);
}

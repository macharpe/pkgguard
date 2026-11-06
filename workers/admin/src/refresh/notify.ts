import { refreshMessage, type SendResult } from "@pkgguard/core";
import { postChat } from "../chat.js";
import type { Env } from "../env.js";
import { getRun } from "./runs.js";

type NotifyEnv = Pick<Env, "DB" | "GCHAT_WEBHOOK" | "PUBLIC_URL">;

/**
 * Tells the Chat space how a run ended: a failure always, a completion only when it changed something or left
 * records to retry. A quiet day is not news. Never throws, so a Chat problem cannot fail or retry a refresh.
 */
export async function notifyRefresh(env: NotifyEnv, runId: string): Promise<SendResult | "not-needed"> {
  try {
    if (!env.GCHAT_WEBHOOK) return "skipped";
    const run = await getRun(env.DB, runId);
    if (run === null) return "skipped";
    if (run.status !== "complete" && run.status !== "failed") return "not-needed";
    if (run.status === "complete" && run.added === 0 && run.errors === 0) return "not-needed";

    const finished = run.finished_at === null ? NaN : Date.parse(run.finished_at) - Date.parse(run.started_at);
    return await postChat(env, refreshMessage({
      status: run.status,
      kind: run.kind,
      trigger: run.trigger,
      added: run.added,
      updated: run.updated,
      removed: run.removed,
      errors: run.errors,
      total: run.items_total,
      seconds: Number.isFinite(finished) && finished >= 0 ? finished / 1000 : null,
      detail: run.error_detail,
      dashboardUrl: env.PUBLIC_URL.startsWith("https://") ? env.PUBLIC_URL : null,
    }));
  } catch {
    console.error("refresh notification failed");
    return "failed";
  }
}

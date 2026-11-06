import { MALWARE_ALERT_TTL_SECONDS, malwareAlertKey, malwareMessage, sendChat, type FetchLike, type MalwareAlert } from "@pkgguard/core";

/** KV's smallest TTL. After a failed send the key lives this long, so the alert is retried soon rather than lost for an hour. */
const RETRY_TTL_SECONDS = 60;

export type AlertResult = "sent" | "skipped" | "rate-limited" | "failed";

export interface AlertDeps {
  kv: Pick<KVNamespace, "get" | "put">;
  fetch: FetchLike;
  webhook: string | undefined;
}

/**
 * At most one malware alert per package per user per hour. Nothing here may affect the download, so the caller runs it in
 * the background and any KV error just means no alert.
 */
export async function maybeAlertMalware(deps: AlertDeps, alert: MalwareAlert): Promise<AlertResult> {
  if (!deps.webhook) return "skipped";
  const key = malwareAlertKey(alert.ecosystem, alert.name, alert.user);
  try {
    if ((await deps.kv.get(key)) !== null) return "rate-limited";
    await deps.kv.put(key, "1", { expirationTtl: MALWARE_ALERT_TTL_SECONDS });
  } catch {
    console.error("alert rate-limit store unavailable; alert not sent");
    return "skipped";
  }
  const result = await sendChat(deps.fetch, deps.webhook, malwareMessage(alert));
  if (result === "failed") {
    await deps.kv.put(key, "1", { expirationTtl: RETRY_TTL_SECONDS }).catch(() => undefined);
    return "failed";
  }
  return result;
}

import {
  ENFORCEMENT_KEY,
  ENFORCEMENT_REFRESH_MS,
  ENFORCEMENT_RETRY_MS,
  enforcementReport,
  parseEnforcementText,
  sameEnforcement,
  type EnforcementReport,
} from "@pkgguard/core";
import type { Settings } from "./env.js";

export type ReportResult = "written" | "unchanged" | "skipped" | "failed";

/** What this isolate last confirmed is in KV, and when it may try again after a failure. Module scope: one per isolate. */
let confirmed: { report: EnforcementReport; atMs: number } | null = null;
let retryAtMs = 0;

/** Test hook. */
export const resetEnforcementReport = (): void => {
  confirmed = null;
  retryAtMs = 0;
};

/**
 * Tells the dashboard what this Worker is actually doing. It runs in the background and nothing here may affect a
 * download, so it never throws and never delays a response.
 *
 * KV allows about one write per second to a single key and many isolates start together, so an isolate reads first and
 * writes only when the stored value differs from its own settings or is older than the refresh interval, and it
 * remembers the outcome so a busy isolate does no KV work on most requests.
 */
export async function reportEnforcement(kv: Pick<KVNamespace, "get" | "put">, settings: Pick<Settings, "enforce" | "observeOnly">, nowMs: number): Promise<ReportResult> {
  const report = enforcementReport(settings, new Date(nowMs).toISOString());
  if (nowMs < retryAtMs) return "skipped";
  if (confirmed && sameEnforcement(confirmed.report, report) && nowMs - confirmed.atMs < ENFORCEMENT_REFRESH_MS) return "skipped";

  try {
    const stored = parseEnforcementText(await kv.get(ENFORCEMENT_KEY));
    const storedAtMs = stored ? Date.parse(stored.reportedAt) : Number.NaN;
    if (stored && sameEnforcement(stored, report) && nowMs - storedAtMs < ENFORCEMENT_REFRESH_MS) {
      confirmed = { report: stored, atMs: storedAtMs };
      return "unchanged";
    }
    await kv.put(ENFORCEMENT_KEY, JSON.stringify(report));
    confirmed = { report, atMs: nowMs };
    return "written";
  } catch {
    retryAtMs = nowMs + ENFORCEMENT_RETRY_MS;
    return "failed";
  }
}

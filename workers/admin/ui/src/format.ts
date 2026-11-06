import type { DetectionVerdict, RefreshRun } from "../../src/api-types.js";

export const plural = (n: number, singular: string, pluralForm = `${singular}s`): string => `${formatCount(n)} ${n === 1 ? singular : pluralForm}`;

export const formatCount = (n: number): string => new Intl.NumberFormat("en").format(n);

/** "just now", "5m ago", "3h ago", "2d ago", then a date. A timestamp in the future reads as "just now". */
export function relativeTime(iso: string, nowMs: number): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "unknown";
  const seconds = Math.floor((nowMs - then) / 1000);
  if (seconds < 45) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(then).toISOString().slice(0, 10);
}

export const osvUrl = (id: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;

export function splitIds(csv: string | null): string[] {
  return csv ? csv.split(",").map((s) => s.trim()).filter(Boolean) : [];
}

export const packageLabel = (name: string, version: string | null): string => (version ? `${name}@${version}` : name);

export type BadgeColour = "red" | "orange" | "green" | "neutral";

export function verdictBadge(verdict: DetectionVerdict): { label: string; colour: BadgeColour } {
  switch (verdict) {
    case "blocked":
      return { label: "Blocked", colour: "red" };
    case "flagged":
      return { label: "Flagged", colour: "orange" };
    case "allowed":
      return { label: "Allowed", colour: "green" };
    case "error":
      return { label: "Lookup error", colour: "neutral" };
  }
}

/** What the filter would do. The Worker only blocks when ENFORCE is on, so this is the policy, not the action taken. */
export function simulationLabel(outcome: DetectionVerdict): string {
  switch (outcome) {
    case "blocked":
      return "Would be blocked";
    case "flagged":
      return "Would be flagged";
    case "allowed":
      return "Would be allowed";
    case "error":
      return "Index entry unreadable";
  }
}

/** "45s", "3m 20s", "1h 05m". */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

export const runDuration = (run: Pick<RefreshRun, "started_at" | "finished_at">): number | null => {
  if (run.finished_at === null) return null;
  const ms = Date.parse(run.finished_at) - Date.parse(run.started_at);
  return Number.isFinite(ms) && ms >= 0 ? ms / 1000 : null;
};

export const isActive = (run: Pick<RefreshRun, "status"> | null | undefined): boolean => run?.status === "queued" || run?.status === "running";

export const kindLabel = (kind: RefreshRun["kind"]): string => ({ manual: "Manual", daily: "Daily", monthly: "Monthly" })[kind];

/** "cron" and "service-token:…" read badly in a table; people are shown as their email. */
export function triggerLabel(trigger: string): string {
  if (trigger === "cron") return "Scheduled";
  if (trigger.startsWith("service-token:")) return "Service token";
  return trigger;
}

export function runSummary(run: Pick<RefreshRun, "status" | "added" | "updated" | "removed" | "errors" | "error_detail">): string {
  if (run.status === "failed") return run.error_detail ?? "Failed";
  if (run.status !== "complete") return "In progress";
  const parts = [`${formatCount(run.added)} added`, `${formatCount(run.updated)} updated`];
  if (run.removed > 0) parts.push(`${formatCount(run.removed)} withdrawn`);
  if (run.errors > 0) parts.push(`${formatCount(run.errors)} to retry`);
  return parts.join(" · ");
}

/** Splits "1.0.0, 1.0.1  2.0.0" into versions; blank means every version. */
export function parseVersionsInput(text: string): string[] | undefined {
  const versions = [...new Set(text.split(/[\s,]+/).filter(Boolean))];
  return versions.length === 0 ? undefined : versions;
}

export function versionsLabel(versions: string[] | null): string {
  if (versions === null) return "All versions";
  const shown = versions.slice(0, 3).join(", ");
  return versions.length > 3 ? `${shown} +${versions.length - 3} more` : shown;
}

import type { DetectionVerdict } from "../../src/api-types.js";

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

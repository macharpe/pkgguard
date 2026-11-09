/**
 * The dashboard's decisions, as pure functions, so they can be tested without a browser: which tab a URL names,
 * which verdicts a view asks for, how a detection becomes an override form, and what the enforcement badge and
 * index pill say. The components only draw what these return.
 */
import { ENABLED_ECOSYSTEMS, ecosystemLabel, type Ecosystem } from "@pkgguard/core/ecosystems";
import type { DetectionRow, EnforcementInfo, OverrideMode, RefreshRunInfo, StatusResponse } from "../../src/api-types.js";
import { formatCount, isActive, relativeTime } from "./format.js";

export const TABS = ["detections", "packages", "index"] as const;
export type TabId = (typeof TABS)[number];

export const TAB_LABELS: Readonly<Record<TabId, string>> = { detections: "Detections", packages: "Packages", index: "Index" };

/** `#packages` names the Packages tab. Anything else, including a hand-edited hash, lands on Detections. */
export function parseTabHash(hash: string): TabId {
  const name = hash.replace(/^#/, "").toLowerCase();
  return (TABS as readonly string[]).includes(name) ? (name as TabId) : "detections";
}

export const tabHash = (tab: TabId): string => `#${tab}`;

export type DetectionView = "attention" | "all";

export const VIEW_LABELS: Readonly<Record<DetectionView, string>> = { attention: "Needs attention", all: "All" };

/** The `verdict` query for a view. One query, not two merged pages, so the "Load older" cursor stays valid. */
export const viewVerdicts = (view: DetectionView): string | undefined => (view === "attention" ? "blocked,flagged" : undefined);

export const isDetectionView = (value: unknown): value is DetectionView => value === "attention" || value === "all";

export interface OverridePrefill {
  mode: OverrideMode;
  ecosystem: Ecosystem;
  /** Exactly as stored: a Go module path is case-sensitive, so it is never lowercased here. */
  name: string;
  /** What the form's Versions box would hold: blank means every version. */
  versions: string;
  note: string;
  source: "detection" | "lookup";
}

/**
 * Turning a detection into an override. What was stopped or flagged is usually a false positive, so the default is
 * to allow it; what was allowed or could not be checked is usually the thing to stop, so the default is to block it.
 * The person can change either in the form.
 */
export function prefillFromDetection(row: Pick<DetectionRow, "id" | "ecosystem" | "package_name" | "version" | "verdict" | "reference">): OverridePrefill {
  return {
    mode: row.verdict === "blocked" || row.verdict === "flagged" ? "allow" : "block",
    ecosystem: row.ecosystem,
    name: row.package_name,
    versions: row.version ?? "",
    note: `From detection ${row.reference ?? `#${row.id}`}`,
    source: "detection",
  };
}

/** Blocking from a lookup covers every version; allowing is scoped to the version that was checked, if any. */
export function prefillFromLookup(mode: OverrideMode, pkg: { ecosystem: Ecosystem; name: string }, version: string): OverridePrefill {
  return { mode, ecosystem: pkg.ecosystem, name: pkg.name, versions: mode === "allow" ? version.trim() : "", note: "", source: "lookup" };
}

/** A prefill someone asked for. A new `nonce` applies it again, so asking twice for the same package still fills the form twice. */
export type PrefillRequest = OverridePrefill & { nonce: number };

export const prefillSummary = (p: Pick<OverridePrefill, "mode" | "name" | "versions" | "source">): string =>
  `Prefilled from a ${p.source}: ${p.mode} ${p.name}${p.versions ? `@${p.versions}` : ""}. Review it, then add.`;

/**
 * One plain sentence on why a download got its verdict. A `flagged` row with a blocking reason means enforcement was
 * off for it, which is the thing worth saying, because it is what makes "flagged" and "blocked" look alike.
 */
export function detectionExplanation(row: Pick<DetectionRow, "verdict" | "reason">): string {
  const wouldBlock = row.verdict === "flagged";
  switch (row.reason) {
    case "osv-malware":
      return wouldBlock
        ? "OSV classifies this release as malware. It was flagged, not blocked, because enforcement was off for this ecosystem."
        : "OSV classifies this release as malware. The download was blocked.";
    case "osv-cve":
      return "OSV lists vulnerabilities for this release. Vulnerabilities are logged, never blocked.";
    case "override":
      if (wouldBlock) return "A block override matches this package. It was flagged, not blocked, because enforcement was off for this ecosystem.";
      return row.verdict === "blocked" ? "A block override matches this package. The download was blocked." : "An allow override matches this package.";
    case "lookup-error":
      return "The live OSV lookup failed, so the download was allowed.";
    default:
      return "No advisories matched this release.";
  }
}

const SOURCES: Readonly<Record<string, string>> = { index: "Index", "live-osv": "Live OSV lookup", override: "Override" };

/** Where the filter got its answer. An id this build does not know is shown as it is. */
export const sourceLabel = (source: string | null): string => (source === null ? "Unknown" : Object.hasOwn(SOURCES, source) ? (SOURCES[source] as string) : source);

export type Tone = "success" | "warning" | "neutral";

export interface EnforcementView {
  kind: "enforcing" | "partial" | "observe" | "unknown";
  tone: Tone;
  label: string;
  detail: string;
  /** Null when nothing has been reported. */
  reportedAt: string | null;
  /** The report is old enough that the filter may have changed since. Its state is still shown. */
  stale: boolean;
}

export const STALE_AFTER_MS = 24 * 60 * 60 * 1000;

/**
 * What the enforcement badge says. A missing report is "not reported", never "off": the filter has simply not
 * spoken since it was deployed. Observe-only ecosystems are limited to the enabled ones, and when every enabled
 * ecosystem is observe-only the filter blocks nothing, so it is called what it is.
 */
export function enforcementView(info: EnforcementInfo | null, nowMs: number, enabled: readonly Ecosystem[] = ENABLED_ECOSYSTEMS): EnforcementView {
  if (info === null) {
    return {
      kind: "unknown",
      tone: "neutral",
      label: "Not reported yet",
      detail: "The filter has not reported its settings since it was last deployed. That does not mean enforcement is off.",
      reportedAt: null,
      stale: false,
    };
  }
  const stale = nowMs - Date.parse(info.reportedAt) > STALE_AFTER_MS;
  const base = { reportedAt: info.reportedAt, stale };
  const observing = enabled.filter((id) => info.observeOnly.includes(id));
  if (!info.enforce) {
    return { ...base, kind: "observe", tone: "warning", label: "Observe-only", detail: "Nothing is blocked. Downloads that would be blocked are recorded as flagged." };
  }
  if (enabled.length > 0 && observing.length === enabled.length) {
    return { ...base, kind: "observe", tone: "warning", label: "Observe-only", detail: "Every ecosystem is observe-only, so nothing is blocked. Would-be blocks are recorded as flagged." };
  }
  if (observing.length > 0) {
    const names = observing.map(ecosystemLabel).join(", ");
    return {
      ...base,
      kind: "partial",
      tone: "warning",
      label: `Enforcing, except ${names}`,
      detail: `${names} ${observing.length === 1 ? "is" : "are"} observe-only: would-be blocks there are recorded as flagged.`,
    };
  }
  return { ...base, kind: "enforcing", tone: "success", label: "Enforcing", detail: "Malware downloads are blocked." };
}

export interface IndexView {
  tone: Tone | "info";
  headline: string;
  detail: string;
  /** 0 to 1 while a refresh is running and its size is known, else null. */
  progress: number | null;
  running: boolean;
}

/**
 * The index pill. A live run (followed once a second by the refresh panel) wins over the status call's copy of the
 * last run, which is up to 30 seconds old, so the pill and the panel agree while a run is going.
 */
export function indexView(status: Pick<StatusResponse, "ecosystems" | "lastRefresh">, liveRun: RefreshRunInfo | null, nowMs: number): IndexView {
  const run = liveRun !== null && isActive(liveRun) ? liveRun : isActive(status.lastRefresh) ? status.lastRefresh : null;
  if (run !== null) {
    const known = run.items_total > 0;
    const progress = known ? Math.min(1, run.items_done / run.items_total) : null;
    return {
      tone: "info",
      headline: progress === null ? "Refreshing" : `Refreshing ${Math.round(progress * 100)}%`,
      detail: run.phase ?? "Starting",
      progress,
      running: true,
    };
  }
  const newest = status.ecosystems.map((e) => e.last_synced_at).sort().at(-1);
  const records = status.ecosystems.reduce((n, e) => n + e.record_count, 0);
  const failed = status.lastRefresh?.status === "failed";
  return {
    tone: failed ? "warning" : "success",
    headline: newest ? `Synced ${relativeTime(newest, nowMs)}` : "Never synced",
    detail: failed ? "The last refresh failed" : `${formatCount(records)} OSV records`,
    progress: null,
    running: false,
  };
}

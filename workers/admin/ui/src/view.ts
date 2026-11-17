/**
 * The dashboard's decisions, as pure functions, so they can be tested without a browser: which tab a URL names,
 * which verdicts a view asks for, how a detection becomes an override form, and what the enforcement badge and
 * index pill say. The components only draw what these return.
 */
import { ENABLED_ECOSYSTEMS, ecosystemLabel, type Ecosystem } from "@pkgguard/core/ecosystems";
import type { CvssRating, DetectionAdvisory, DetectionRow, EnforcementInfo, OverrideMode, RefreshRunInfo, StatusResponse } from "../../src/api-types.js";
import { formatCount, isActive, plural, relativeTime, type BadgeColour } from "./format.js";

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

// ---------------------------------------------------------------------------------------------------------------------
// Severity badges
// ---------------------------------------------------------------------------------------------------------------------

export type SeverityCategory = "none" | "low" | "moderate" | "high" | "critical";

const CATEGORY_RANK: Readonly<Record<SeverityCategory, number>> = { none: 0, low: 1, moderate: 2, high: 3, critical: 4 };

export const CATEGORY_LABELS: Readonly<Record<SeverityCategory, string>> = { none: "None", low: "Low", moderate: "Moderate", high: "High", critical: "Critical" };

const CATEGORY_COLOURS: Readonly<Record<SeverityCategory, BadgeColour>> = { none: "secondary", low: "info", moderate: "warning", high: "error", critical: "error" };

/** The CVSS qualitative scale: 0 is None, below 4 Low, below 7 Moderate (CVSS calls it Medium), below 9 High, then Critical. */
export function cvssCategory(score: number): SeverityCategory {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "moderate";
  return score > 0 ? "low" : "none";
}

/** A usable base score is a finite number from 0 to 10. Anything else is treated as no score, never as 0. */
export const isUsableScore = (score: unknown): score is number => typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 10;

/** The word an advisory carries when it has no score (GitHub's `LOW`/`MODERATE`/`HIGH`/`CRITICAL`; `MEDIUM` is the same band). Anything else, such as a vector string, is not a label. */
export function categoryFromLabel(severity: string | null | undefined): SeverityCategory | null {
  switch (severity?.trim().toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "moderate";
    case "LOW":
      return "low";
    case "NONE":
      return "none";
    default:
      return null;
  }
}

/** What both a detection's advisory and a lookup row carry. */
export type AdvisoryInput = Pick<DetectionAdvisory, "osv_id" | "kind" | "severity"> & { cvss?: CvssRating | null | undefined; status?: DetectionAdvisory["status"] | undefined };

export interface AdvisoryAssessment {
  osvId: string;
  kind: "malware" | "vulnerability" | null;
  /** Null when the advisory has neither a usable score nor a recognised label. */
  category: SeverityCategory | null;
  /** Where the category came from: the calculated score wins over the advisory's own label. */
  basis: "cvss" | "label" | null;
  /** Null for malware, whatever the source supplied: malware is not scored. */
  rating: CvssRating | null;
}

export function assessAdvisory(advisory: AdvisoryInput): AdvisoryAssessment {
  const base = { osvId: advisory.osv_id, kind: advisory.kind };
  if (advisory.status === "withdrawn" || advisory.status === "not-indexed" || advisory.kind === "malware") return { ...base, category: null, basis: null, rating: null };
  const rating = advisory.cvss && isUsableScore(advisory.cvss.score) ? advisory.cvss : null;
  if (rating) return { ...base, category: cvssCategory(rating.score), basis: "cvss", rating };
  const fromLabel = categoryFromLabel(advisory.severity);
  return { ...base, category: fromLabel, basis: fromLabel ? "label" : null, rating: null };
}

export interface SeveritySummary {
  /** The most severe rated advisory, a higher score first among equals. Null when none is rated. */
  highest: AdvisoryAssessment | null;
  rated: number;
  /** Vulnerabilities with no usable score and no recognised label in the current index. */
  unrated: number;
  total: number;
}

const score = (a: AdvisoryAssessment): number => a.rating?.score ?? -1;

/**
 * The highest severity over the vulnerabilities in a list. Malware is not a vulnerability and never counts. An advisory
 * with a label but no score still counts at its label, so it cannot be hidden behind a lower scored one.
 */
export function summariseSeverity(advisories: readonly AdvisoryInput[]): SeveritySummary {
  const vulns = advisories.filter((a) => a.kind !== "malware").map(assessAdvisory);
  let highest: AdvisoryAssessment | null = null;
  for (const a of vulns) {
    if (a.category === null) continue;
    if (highest === null || CATEGORY_RANK[a.category] > CATEGORY_RANK[highest.category as SeverityCategory] || (a.category === highest.category && score(a) > score(highest))) highest = a;
  }
  const rated = vulns.filter((a) => a.category !== null).length;
  return { highest, rated, unrated: vulns.length - rated, total: vulns.length };
}

export const SEVERITY_DISCLAIMER =
  "Severity is read from the index as it is now, not as it was when this download happened. A score is a CVSS base score for the vulnerability that OSV supplied; it is not a risk score for this package.";

/** "CVSS v3.1" from "3.1", "CVSS_V3" or "v3.1". */
export function cvssVersionLabel(version: string): string {
  const rest = version.trim().replace(/^cvss[\s_:-]*/i, "").replace(/^v/i, "");
  return rest === "" ? "CVSS" : `CVSS v${rest}`;
}

export const formatScore = (n: number): string => n.toFixed(1);

export interface SeverityBadgeView {
  kind: "malware" | "severity" | "unrated";
  label: string;
  colour: BadgeColour;
  /** The hover text: what the badge is based on, and how many advisories it does not cover. */
  title: string;
}

const MALWARE_BADGE: SeverityBadgeView = { kind: "malware", label: "Malware", colour: "error", title: "OSV classifies this release as malware. Malware is not given a severity score." };

export const malwareBadge = (): SeverityBadgeView => MALWARE_BADGE;

const basisText = (a: AdvisoryAssessment): string => (a.rating ? `${cvssVersionLabel(a.rating.version)} base score ${formatScore(a.rating.score)}` : "the advisory's own severity label, which has no score");

/** The badge for a summary of vulnerabilities. Null when there is nothing to say. */
export function severityBadge(summary: SeveritySummary): SeverityBadgeView | null {
  if (summary.total === 0) return null;
  const { highest, rated, unrated, total } = summary;
  if (highest === null || highest.category === null) {
    return {
      kind: "unrated",
      label: "Unrated",
      colour: "secondary",
      title: `${plural(total, "advisory", "advisories")} ${total === 1 ? "has" : "have"} no score or severity label in the current index.`,
    };
  }
  const name = CATEGORY_LABELS[highest.category];
  const missing = unrated > 0 ? ` ${unrated} of ${total} ${total === 1 ? "advisory has" : "advisories have"} no score or severity label, so ${unrated === 1 ? "it is" : "they are"} not covered.` : "";
  const scope = total > 1 ? `Highest of ${rated} rated ${rated === 1 ? "advisory" : "advisories"}` : "Rated";
  return {
    kind: "severity",
    label: `${name}${highest.rating ? ` · ${formatScore(highest.rating.score)}` : ""}${unrated > 0 ? ` · ${unrated} unrated` : ""}`,
    colour: CATEGORY_COLOURS[highest.category],
    title: `${scope}: ${name}, from ${basisText(highest)} (${highest.osvId}), current index.${missing}`,
  };
}

/**
 * The badge in a detection's Package cell. A malware decision is Malware whatever its verdict (blocked or flagged);
 * a CVE decision shows the highest severity of the advisories it recorded. An override, a clean pass or a failed
 * lookup says nothing about advisories, so it gets no badge: severity is never invented for them.
 */
export function detectionSeverityBadge(row: Pick<DetectionRow, "reason" | "advisories">): SeverityBadgeView | null {
  if (row.reason === "osv-malware") return MALWARE_BADGE;
  if (row.reason !== "osv-cve") return null;
  const summary = summariseSeverity(row.advisories ?? []);
  // A row recorded before advisories were returned, or whose advisories have left the index: still a CVE decision, but nothing to rate.
  if (summary.total === 0) return { kind: "unrated", label: "Unrated", colour: "secondary", title: "No severity metadata is available for the advisories recorded with this download in the current index." };
  return severityBadge(summary);
}

/** The badge for one advisory in a list: Malware for malware, else its own severity. */
export function advisoryBadge(advisory: AdvisoryInput): SeverityBadgeView | null {
  return advisory.kind === "malware" ? MALWARE_BADGE : severityBadge(summariseSeverity([advisory]));
}

export interface AdvisoryDetailView {
  osvId: string;
  /** Null when there is nothing beyond the badge, so no expander is drawn. */
  lines: string[] | null;
  vector: string | null;
  source: string | null;
}

/** The expandable text for one advisory: the score and its version, the vector and where it came from. */
export function advisoryDetail(advisory: AdvisoryInput): AdvisoryDetailView {
  const a = assessAdvisory(advisory);
  const base = { osvId: a.osvId, vector: null, source: null };
  // A withdrawn or unindexed advisory has nothing current to score: say that, whatever the recorded id once was.
  if (advisory.status === "withdrawn") return { ...base, lines: ["Withdrawn in the current index. No current severity is available."] };
  if (advisory.status === "not-indexed") return { ...base, lines: ["Not in the current index. No severity is available."] };
  if (a.kind === "malware") return { ...base, lines: null };
  if (a.rating && a.category) {
    const { rating } = a;
    return {
      osvId: a.osvId,
      lines: [`${cvssVersionLabel(rating.version)} base score ${formatScore(rating.score)} (${CATEGORY_LABELS[a.category]})`],
      vector: rating.vector,
      source: rating.source,
    };
  }
  if (a.category) return { ...base, lines: [`Severity label ${CATEGORY_LABELS[a.category]}. No score is available.`] };
  return { ...base, lines: ["No score or severity label in the current index."] };
}

/** Shown above a lookup's advisory lists: they are everything known for the package, and a version only narrows the verdict above them. */
export function lookupAdvisoryNote(version: string): string {
  const v = version.trim();
  return v === ""
    ? "These are all the advisories known for this package, across every version."
    : `These are all the advisories known for this package, not only those that affect ${v}. The result above is what the filter decides for that version.`;
}

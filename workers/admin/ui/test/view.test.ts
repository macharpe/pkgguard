import { ENABLED_ECOSYSTEMS } from "@pkgguard/core/ecosystems";
import { describe, expect, it } from "vitest";
import type { CvssRating, DetectionAdvisory, DetectionRow, EnforcementInfo, RefreshRunInfo } from "../../src/api-types.js";
import { CATEGORY_LABELS, SEVERITY_DISCLAIMER, STALE_AFTER_MS, TABS, advisoryBadge, advisoryDetail, assessAdvisory, categoryFromLabel, cvssCategory, cvssVersionLabel, detectionExplanation, detectionSeverityBadge, lookupAdvisoryNote, severityBadge, summariseSeverity, enforcementView, indexView, isDetectionView, parseTabHash, prefillFromDetection, prefillFromLookup, prefillSummary, sourceLabel, tabHash, viewVerdicts } from "../src/view.js";

const NOW = Date.parse("2026-11-09T12:00:00Z");
const at = (secondsAgo: number) => new Date(NOW - secondsAgo * 1000).toISOString();

describe("tabs", () => {
  it.each([
    ["#detections", "detections"],
    ["#packages", "packages"],
    ["#index", "index"],
    ["packages", "packages"],
    ["#Packages", "packages"],
    ["#INDEX", "index"],
  ])("%j names the %s tab", (hash, tab) => {
    expect(parseTabHash(hash)).toBe(tab);
  });
  it.each(["", "#", "#nope", "#overrides", "#detections/extra", "##packages", "# packages", "#__proto__", "#constructor", "#toString"])("falls back to Detections for %j", (hash) => {
    expect(parseTabHash(hash)).toBe("detections");
  });
  it("writes the hash with a leading #, which is what the address bar needs", () => {
    expect(tabHash("packages")).toBe("#packages");
    for (const tab of TABS) expect(tabHash(tab)).toBe(`#${tab}`);
  });
  it("round-trips every tab through its hash", () => {
    for (const tab of TABS) expect(parseTabHash(tabHash(tab))).toBe(tab);
  });
  it("starts on Detections", () => {
    expect(TABS[0]).toBe("detections");
  });
});

describe("detection views", () => {
  it("asks for blocked and flagged only under Needs attention, as one query", () => {
    expect(viewVerdicts("attention")).toBe("blocked,flagged");
  });
  it("asks for no verdict filter under All", () => {
    expect(viewVerdicts("all")).toBeUndefined();
  });
  it("recognises only the two views", () => {
    expect(isDetectionView("attention")).toBe(true);
    expect(isDetectionView("all")).toBe(true);
    for (const v of ["", "All", "blocked", null, undefined, 3]) expect(isDetectionView(v)).toBe(false);
  });
});

const row = (over: Partial<DetectionRow> = {}): DetectionRow => ({
  id: 7,
  ts: at(60),
  ecosystem: "npm",
  package_name: "lodash",
  version: "4.17.20",
  purl: null,
  verdict: "flagged",
  reason: "osv-cve",
  osv_ids: null,
  user_email: null,
  src_ip: null,
  source: "index",
  reference: null,
  ...over,
});

describe("prefillFromDetection", () => {
  it.each([
    ["blocked", "allow"],
    ["flagged", "allow"],
    ["allowed", "block"],
    ["error", "block"],
  ] as const)("a %s detection defaults to %s", (verdict, mode) => {
    expect(prefillFromDetection(row({ verdict })).mode).toBe(mode);
  });
  it("carries the ecosystem and the version", () => {
    expect(prefillFromDetection(row({ ecosystem: "pypi", package_name: "ctx", version: "0.1.2" }))).toMatchObject({ ecosystem: "pypi", name: "ctx", versions: "0.1.2", source: "detection" });
  });
  it("leaves the versions blank, meaning every version, when the row has none", () => {
    expect(prefillFromDetection(row({ version: null })).versions).toBe("");
  });
  it("keeps the name exactly as stored, so a case-sensitive Go module path is never lowercased", () => {
    const name = "github.com/Azure/azure-sdk-for-go/sdk/azcore";
    expect(prefillFromDetection(row({ ecosystem: "go", package_name: name, version: "v1.2.3" }))).toMatchObject({ name, versions: "v1.2.3" });
    expect(prefillFromDetection(row({ package_name: "@Scope/Name" })).name).toBe("@Scope/Name");
  });
  it("points the note at the reference the developer quoted, else at the row", () => {
    expect(prefillFromDetection(row({ reference: "PG-7Q2K4M" })).note).toBe("From detection PG-7Q2K4M");
    expect(prefillFromDetection(row({ reference: null, id: 42 })).note).toBe("From detection #42");
  });
});

describe("prefillFromLookup", () => {
  const pkg = { ecosystem: "npm", name: "event-stream" } as const;
  it("blocks every version, whatever version was checked", () => {
    expect(prefillFromLookup("block", pkg, "3.3.6")).toMatchObject({ mode: "block", versions: "", name: "event-stream", source: "lookup" });
  });
  it("allows only the version that was checked", () => {
    expect(prefillFromLookup("allow", pkg, " 3.3.6 ").versions).toBe("3.3.6");
  });
  it("allows every version when none was checked", () => {
    expect(prefillFromLookup("allow", pkg, "").versions).toBe("");
  });
  it("keeps the name exactly as the index has it", () => {
    expect(prefillFromLookup("block", { ecosystem: "go", name: "github.com/Foo/Bar" }, "").name).toBe("github.com/Foo/Bar");
  });
});

describe("prefillSummary", () => {
  it("says what was filled in and where from", () => {
    expect(prefillSummary({ mode: "allow", name: "lodash", versions: "4.17.20", source: "detection" })).toBe("Prefilled from a detection: allow lodash@4.17.20. Review it, then add.");
    expect(prefillSummary({ mode: "block", name: "evil", versions: "", source: "lookup" })).toBe("Prefilled from a lookup: block evil. Review it, then add.");
  });
});

describe("detectionExplanation", () => {
  it("says a blocked malware download was blocked", () => {
    expect(detectionExplanation({ verdict: "blocked", reason: "osv-malware" })).toBe("OSV classifies this release as malware. The download was blocked.");
  });
  it("says why a malware download that was only flagged was not blocked", () => {
    const text = detectionExplanation({ verdict: "flagged", reason: "osv-malware" });
    expect(text).toContain("flagged, not blocked");
    expect(text).toContain("enforcement was off");
  });
  it("says vulnerabilities are logged, never blocked", () => {
    expect(detectionExplanation({ verdict: "flagged", reason: "osv-cve" })).toContain("logged, never blocked");
  });
  it("tells a block override that stopped the download from one that was only flagged", () => {
    expect(detectionExplanation({ verdict: "blocked", reason: "override" })).toBe("A block override matches this package. The download was blocked.");
    expect(detectionExplanation({ verdict: "flagged", reason: "override" })).toContain("enforcement was off");
  });
  it("recognises an allow override", () => {
    expect(detectionExplanation({ verdict: "allowed", reason: "override" })).toBe("An allow override matches this package.");
  });
  it("says a failed lookup let the download through", () => {
    expect(detectionExplanation({ verdict: "error", reason: "lookup-error" })).toContain("allowed");
  });
  it("says nothing matched when there is no reason", () => {
    expect(detectionExplanation({ verdict: "allowed", reason: null })).toBe("No advisories matched this release.");
  });
});

describe("sourceLabel", () => {
  it("names the three sources the filter writes", () => {
    expect(sourceLabel("index")).toBe("Index");
    expect(sourceLabel("live-osv")).toBe("Live OSV lookup");
    expect(sourceLabel("override")).toBe("Override");
  });
  it("shows an unknown source as it is, and a missing one as unknown", () => {
    expect(sourceLabel("something-new")).toBe("something-new");
    expect(sourceLabel(null)).toBe("Unknown");
    expect(sourceLabel("constructor")).toBe("constructor");
    expect(sourceLabel("__proto__")).toBe("__proto__");
  });
});

const info = (over: Partial<EnforcementInfo> = {}): EnforcementInfo => ({ enforce: true, observeOnly: [], reportedAt: at(240), ...over });

describe("enforcementView", () => {
  it("calls a missing report 'not reported', and never says enforcement is off", () => {
    const v = enforcementView(null, NOW);
    expect(v).toMatchObject({ kind: "unknown", tone: "neutral", label: "Not reported yet", reportedAt: null, stale: false });
    expect(v.detail).toContain("does not mean enforcement is off");
  });
  it("is enforcing when enforcing with nothing observe-only", () => {
    expect(enforcementView(info(), NOW)).toMatchObject({ kind: "enforcing", tone: "success", label: "Enforcing" });
  });
  it("is observe-only when not enforcing, whatever the list says", () => {
    expect(enforcementView(info({ enforce: false }), NOW)).toMatchObject({ kind: "observe", tone: "warning", label: "Observe-only" });
    expect(enforcementView(info({ enforce: false, observeOnly: ["pypi"] }), NOW)).toMatchObject({ kind: "observe", label: "Observe-only" });
  });
  it("names the observe-only ecosystems with their labels", () => {
    const one = enforcementView(info({ observeOnly: ["pypi"] }), NOW);
    expect(one).toMatchObject({ kind: "partial", tone: "warning", label: "Enforcing, except PyPI" });
    expect(one.detail).toContain("PyPI is observe-only");
    const two = enforcementView(info({ observeOnly: ["pypi", "go"] }), NOW);
    expect(two.label).toBe("Enforcing, except PyPI, Go");
    expect(two.detail).toContain("PyPI, Go are observe-only");
  });
  it("is observe-only when every enabled ecosystem is observe-only, even though enforce is on", () => {
    const all = enforcementView(info({ observeOnly: [...ENABLED_ECOSYSTEMS] }), NOW);
    expect(all).toMatchObject({ kind: "observe", tone: "warning", label: "Observe-only" });
    expect(all.detail).toContain("Every ecosystem");
  });
  it("is partial, not observe-only, while at least one enabled ecosystem still blocks", () => {
    expect(enforcementView(info({ observeOnly: ENABLED_ECOSYSTEMS.slice(1) as never }), NOW).kind).toBe("partial");
  });
  it("only counts observe-only ids that are enabled", () => {
    expect(enforcementView(info({ observeOnly: ["go"] }), NOW, ["npm", "pypi"]).kind).toBe("enforcing");
    expect(enforcementView(info({ observeOnly: ["npm", "pypi", "go"] }), NOW, ["npm", "pypi"]).kind).toBe("observe");
  });
  it("carries the time reported", () => {
    expect(enforcementView(info({ reportedAt: at(10) }), NOW).reportedAt).toBe(at(10));
  });
  it("marks a report older than a day as stale, but still shows what it said", () => {
    const old = enforcementView(info({ reportedAt: at(STALE_AFTER_MS / 1000 + 1) }), NOW);
    expect(old).toMatchObject({ stale: true, kind: "enforcing", label: "Enforcing" });
    expect(enforcementView(info({ reportedAt: at(STALE_AFTER_MS / 1000 - 1) }), NOW).stale).toBe(false);
    expect(enforcementView(info({ reportedAt: at(STALE_AFTER_MS / 1000) }), NOW).stale).toBe(false);
  });
  it("does not call a report from the future stale", () => {
    expect(enforcementView(info({ reportedAt: at(-3600) }), NOW).stale).toBe(false);
  });
});

const synced = (ecosystem: string, secondsAgo: number, records: number) => ({ ecosystem, last_modified: at(secondsAgo), record_count: records, last_synced_at: at(secondsAgo) }) as never;
const run = (over: Partial<RefreshRunInfo> = {}): RefreshRunInfo => ({
  id: "r1",
  kind: "manual",
  trigger: "cron",
  status: "running",
  phase: "fetching records",
  items_done: 0,
  items_total: 0,
  added: 0,
  updated: 0,
  removed: 0,
  errors: 0,
  error_detail: null,
  started_at: at(30),
  finished_at: null,
  etaSeconds: null,
  ...over,
});
const settled = { ecosystems: [synced("npm", 7200, 300), synced("pypi", 9000, 120)], lastRefresh: null };

describe("indexView", () => {
  it("says when the newest ecosystem synced and how many records there are, in total", () => {
    expect(indexView(settled, null, NOW)).toEqual({ tone: "success", headline: "Synced 2h ago", detail: "420 OSV records", progress: null, running: false });
  });
  it("uses the newest sync, not the first", () => {
    expect(indexView({ ecosystems: [synced("npm", 90000, 1), synced("pypi", 600, 1)], lastRefresh: null }, null, NOW).headline).toBe("Synced 10m ago");
  });
  it("says 'never synced' with nothing loaded", () => {
    expect(indexView({ ecosystems: [], lastRefresh: null }, null, NOW)).toMatchObject({ headline: "Never synced", detail: "0 OSV records" });
  });
  it("warns when the last refresh failed, and still says when it last synced", () => {
    const v = indexView({ ...settled, lastRefresh: run({ status: "failed", error_detail: "boom" }) }, null, NOW);
    expect(v).toMatchObject({ tone: "warning", headline: "Synced 2h ago", detail: "The last refresh failed", running: false });
  });
  it("shows progress for a live run, rounded", () => {
    const v = indexView(settled, run({ items_done: 720, items_total: 1800 }), NOW);
    expect(v).toEqual({ tone: "info", headline: "Refreshing 40%", detail: "fetching records", progress: 0.4, running: true });
  });
  it("rounds the percentage to the nearest whole number, not down", () => {
    expect(indexView(settled, run({ items_done: 2, items_total: 3 }), NOW).headline).toBe("Refreshing 67%");
    expect(indexView(settled, run({ items_done: 1, items_total: 3 }), NOW).headline).toBe("Refreshing 33%");
  });
  it("shows an unsized run as refreshing without a percentage", () => {
    expect(indexView(settled, run({ items_total: 0 }), NOW)).toMatchObject({ headline: "Refreshing", progress: null, running: true });
  });
  it("never goes past 100%", () => {
    expect(indexView(settled, run({ items_done: 50, items_total: 10 }), NOW)).toMatchObject({ headline: "Refreshing 100%", progress: 1 });
  });
  it("falls back to the status call's copy of the last run while it is active", () => {
    const v = indexView({ ...settled, lastRefresh: run({ status: "queued", phase: null, items_done: 10, items_total: 100 }) }, null, NOW);
    expect(v).toMatchObject({ headline: "Refreshing 10%", detail: "Starting", running: true });
  });
  it("prefers the live run over the status call's older copy", () => {
    const v = indexView({ ...settled, lastRefresh: run({ items_done: 10, items_total: 100 }) }, run({ items_done: 90, items_total: 100 }), NOW);
    expect(v.headline).toBe("Refreshing 90%");
  });
  it("ignores a live run that has finished", () => {
    expect(indexView(settled, run({ status: "complete" }), NOW).running).toBe(false);
    expect(indexView(settled, run({ status: "failed" }), NOW).running).toBe(false);
  });
});

const rating = (score: number, over: Partial<CvssRating> = {}): CvssRating => ({ score, version: "3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source: "GitHub", ...over });
const vuln = (osv_id: string, over: Partial<DetectionAdvisory> = {}): DetectionAdvisory => ({ osv_id, kind: "vulnerability", severity: null, cvss: null, ...over });

describe("cvssCategory", () => {
  it.each([
    [0, "none"],
    [0.1, "low"],
    [3.9, "low"],
    [4, "moderate"],
    [6.9, "moderate"],
    [7, "high"],
    [8.9, "high"],
    [9, "critical"],
    [10, "critical"],
  ] as const)("scores %s as %s", (score, category) => {
    expect(cvssCategory(score)).toBe(category);
  });
});

describe("categoryFromLabel", () => {
  it.each([
    ["CRITICAL", "critical"],
    ["high", "high"],
    [" Moderate ", "moderate"],
    ["MEDIUM", "moderate"],
    ["LOW", "low"],
  ] as const)("reads %j as %s", (label, category) => {
    expect(categoryFromLabel(label)).toBe(category);
  });
  it.each([null, undefined, "", "CVSS:3.1/AV:N/AC:L", "9.8", "severe"])("does not read %j as a label", (label) => {
    expect(categoryFromLabel(label)).toBeNull();
  });
});

describe("assessAdvisory", () => {
  it("lets a score decide the category over the advisory's own label", () => {
    expect(assessAdvisory(vuln("A", { severity: "LOW", cvss: rating(9.8) }))).toMatchObject({ category: "critical", basis: "cvss" });
  });
  it("falls back to the label when there is no score", () => {
    expect(assessAdvisory(vuln("A", { severity: "HIGH" }))).toMatchObject({ category: "high", basis: "label", rating: null });
  });
  it("treats a score outside 0 to 10 or not a number as no score, not as zero", () => {
    for (const score of [Number.NaN, 11, -1, Number.POSITIVE_INFINITY]) {
      expect(assessAdvisory(vuln("A", { cvss: rating(score) }))).toMatchObject({ category: null, rating: null });
    }
  });
  it("has no category for an advisory with neither", () => {
    expect(assessAdvisory(vuln("A"))).toMatchObject({ category: null, basis: null });
  });
  it("never gives malware a score, even when the source supplied one", () => {
    const a = assessAdvisory({ osv_id: "MAL-1", kind: "malware", severity: "CRITICAL", cvss: rating(10) });
    expect(a).toMatchObject({ category: null, rating: null });
  });
});

describe("summariseSeverity", () => {
  it("picks the highest category, and the higher score within it", () => {
    const s = summariseSeverity([vuln("A", { cvss: rating(7.1) }), vuln("B", { cvss: rating(8.8) }), vuln("C", { cvss: rating(5) })]);
    expect(s.highest?.osvId).toBe("B");
    expect(s).toMatchObject({ rated: 3, unrated: 0, total: 3 });
  });
  it("does not hide a higher label-only finding behind a lower score", () => {
    const s = summariseSeverity([vuln("A", { cvss: rating(5.3) }), vuln("B", { severity: "CRITICAL" })]);
    expect(s.highest).toMatchObject({ osvId: "B", category: "critical", basis: "label" });
  });
  it("counts an advisory with nothing as unrated", () => {
    expect(summariseSeverity([vuln("A", { cvss: rating(5) }), vuln("B"), vuln("C")])).toMatchObject({ rated: 1, unrated: 2, total: 3 });
  });
  it("leaves malware out of the vulnerability summary", () => {
    const s = summariseSeverity([{ osv_id: "MAL-1", kind: "malware", severity: null }, vuln("A", { cvss: rating(3) })]);
    expect(s).toMatchObject({ total: 1, rated: 1 });
    expect(s.highest?.osvId).toBe("A");
  });
  it("is empty for no advisories", () => {
    expect(summariseSeverity([])).toEqual({ highest: null, rated: 0, unrated: 0, total: 0 });
  });
});

describe("severityBadge", () => {
  it("is absent when there are no vulnerabilities", () => {
    expect(severityBadge(summariseSeverity([]))).toBeNull();
  });
  it("names the category and the basis for one rated advisory", () => {
    const b = severityBadge(summariseSeverity([vuln("GHSA-1", { cvss: rating(9.8) })]));
    expect(b).toMatchObject({ kind: "severity", label: "Critical · 9.8", colour: "error" });
    expect(b?.title).toContain("CVSS v3.1 base score 9.8");
    expect(b?.title).toContain("GHSA-1");
    expect(b?.title).toContain("current index");
  });
  it.each([
    [2, "Low · 2.0", "info"],
    [5, "Moderate · 5.0", "warning"],
    [7.5, "High · 7.5", "error"],
    [8.1, "High · 8.1", "error"],
    [9.8, "Critical · 9.8", "error"],
    [10, "Critical · 10.0", "error"],
  ] as const)("shows a %s as %s with the %s variant", (score, label, colour) => {
    expect(severityBadge(summariseSeverity([vuln("A", { cvss: rating(score) })]))).toMatchObject({ label, colour });
  });
  it("shows a score of 0 as None, in a neutral colour", () => {
    expect(severityBadge(summariseSeverity([vuln("A", { cvss: rating(0) })]))).toMatchObject({ label: "None · 0.0", colour: "secondary" });
  });
  it("says in the label, not only the tooltip, that some advisories are not covered", () => {
    const b = severityBadge(summariseSeverity([vuln("A", { cvss: rating(7.5) }), vuln("B"), vuln("C")]));
    expect(b?.label).toBe("High · 7.5 · 2 unrated");
    expect(b?.title).toContain("Highest of 1 rated advisory");
    expect(b?.title).toContain("2 of 3 advisories have no score or severity label");
  });
  it("does not imply every advisory is rated when all are rated and there are several", () => {
    const b = severityBadge(summariseSeverity([vuln("A", { cvss: rating(7.5) }), vuln("B", { cvss: rating(4) })]));
    expect(b?.label).toBe("High · 7.5");
    expect(b?.title).toContain("Highest of 2 rated advisories");
  });
  it("is Unrated when no advisory has a score or label", () => {
    expect(severityBadge(summariseSeverity([vuln("A"), vuln("B")]))).toMatchObject({ kind: "unrated", label: "Unrated", colour: "secondary" });
  });
  it("uses only soft variants", () => {
    for (const score of [0, 2, 5, 8, 10]) expect(["error", "warning", "success", "info", "secondary"]).toContain(severityBadge(summariseSeverity([vuln("A", { cvss: rating(score) })]))?.colour);
  });
});

describe("categorical-only labels", () => {
  it("shows the category without a number when the advisory has only a label", () => {
    expect(severityBadge(summariseSeverity([vuln("A", { severity: "CRITICAL" })]))).toMatchObject({ label: "Critical", colour: "error" });
    expect(severityBadge(summariseSeverity([vuln("A", { severity: "MODERATE" })]))?.label).toBe("Moderate");
  });
  it("shows no score for a label-only highest, even when a lower scored advisory exists", () => {
    expect(severityBadge(summariseSeverity([vuln("A", { cvss: rating(5.3) }), vuln("B", { severity: "CRITICAL" })]))?.label).toBe("Critical");
  });
  it("adds the unrated count after a label-only category", () => {
    expect(severityBadge(summariseSeverity([vuln("A", { severity: "HIGH" }), vuln("B")]))?.label).toBe("High · 1 unrated");
  });
});

describe("withdrawn and not-indexed advisories", () => {
  it("says a withdrawn advisory has no current severity, with no score or vector", () => {
    const d = advisoryDetail(vuln("A", { status: "withdrawn", cvss: rating(9.8) }));
    expect(d.lines?.[0]).toContain("Withdrawn");
    expect(d).toMatchObject({ vector: null, source: null });
  });
  it("says a not-indexed advisory is not in the current index", () => {
    expect(advisoryDetail(vuln("A", { kind: null, status: "not-indexed" })).lines?.[0]).toContain("Not in the current index");
  });
  it("shows the score as usual for a current advisory", () => {
    expect(advisoryDetail(vuln("A", { status: "current", cvss: rating(7.5) })).lines?.[0]).toContain("7.5");
  });
});

describe("lookupAdvisoryNote", () => {
  it("says the list covers every version when none was checked", () => {
    expect(lookupAdvisoryNote("")).toContain("across every version");
  });
  it("says the list is not limited to the checked version", () => {
    expect(lookupAdvisoryNote(" 4.17.20 ")).toContain("not only those that affect 4.17.20");
  });
});

describe("detectionSeverityBadge", () => {
  it("shows Malware for an osv-malware reason, from the reason alone: the verdict (blocked or flagged) is not an input", () => {
    expect(detectionSeverityBadge({ reason: "osv-malware" })).toMatchObject({ kind: "malware", label: "Malware", colour: "error" });
    expect(detectionSeverityBadge({ reason: "osv-malware", advisories: [] })).toMatchObject({ kind: "malware" });
  });
  it("shows Malware without a numeric score even when the recorded advisory carries one", () => {
    const b = detectionSeverityBadge({ reason: "osv-malware", advisories: [{ osv_id: "MAL-1", kind: "malware", severity: "CRITICAL", cvss: rating(10) }] });
    expect(b?.label).toBe("Malware");
    expect(b?.title).not.toMatch(/10\.0/);
  });
  it("does not let a malware row be rated like a vulnerability", () => {
    expect(detectionSeverityBadge({ reason: "osv-malware", advisories: [vuln("A", { cvss: rating(2) })] })?.kind).toBe("malware");
  });
  it("rates an osv-cve row by its highest advisory", () => {
    expect(detectionSeverityBadge({ reason: "osv-cve", advisories: [vuln("A", { cvss: rating(5) }), vuln("B", { cvss: rating(9.1) })] })).toMatchObject({ label: "Critical · 9.1" });
  });
  it("is Unrated for an osv-cve row with no advisory metadata at all (older API, or advisories gone from the index)", () => {
    expect(detectionSeverityBadge({ reason: "osv-cve" })).toMatchObject({ kind: "unrated", label: "Unrated" });
    expect(detectionSeverityBadge({ reason: "osv-cve", advisories: [] })).toMatchObject({ kind: "unrated", label: "Unrated" });
  });
  it("is Unrated for an osv-cve row whose advisories are unscored", () => {
    expect(detectionSeverityBadge({ reason: "osv-cve", advisories: [vuln("A", { kind: null })] })).toMatchObject({ kind: "unrated" });
  });
  it.each(["override", "lookup-error", null] as const)("invents no badge for reason %s", (reason) => {
    expect(detectionSeverityBadge({ reason, advisories: [vuln("A", { cvss: rating(9.9) })] })).toBeNull();
  });
});

describe("advisoryBadge and advisoryDetail", () => {
  it("badges malware as Malware and shows no score detail", () => {
    const m = { osv_id: "MAL-1", kind: "malware" as const, severity: null, cvss: rating(10) };
    expect(advisoryBadge(m)?.label).toBe("Malware");
    expect(advisoryDetail(m)).toEqual({ osvId: "MAL-1", lines: null, vector: null, source: null });
  });
  it("shows the score, version, vector and source for a scored vulnerability", () => {
    const d = advisoryDetail(vuln("A", { cvss: rating(7.5, { version: "4.0", source: "NVD", vector: "CVSS:4.0/AV:N" }) }));
    expect(d.lines).toEqual(["CVSS v4.0 base score 7.5 (High)"]);
    expect(d).toMatchObject({ vector: "CVSS:4.0/AV:N", source: "NVD" });
  });
  it("says a label-only advisory has no score", () => {
    expect(advisoryDetail(vuln("A", { severity: "MODERATE" })).lines?.[0]).toContain("No score is available");
  });
  it("says so when there is nothing", () => {
    expect(advisoryDetail(vuln("A")).lines?.[0]).toContain("No score or severity label");
    expect(advisoryBadge(vuln("A"))).toMatchObject({ kind: "unrated" });
  });
});

describe("severity copy", () => {
  it("tells the reader the severity is current index metadata, not a historic snapshot or a risk score", () => {
    expect(SEVERITY_DISCLAIMER).toContain("as it is now");
    expect(SEVERITY_DISCLAIMER).toContain("not a risk score");
  });
  it("names every category", () => {
    expect(Object.values(CATEGORY_LABELS)).toEqual(["None", "Low", "Moderate", "High", "Critical"]);
  });
  it.each([
    ["3.1", "CVSS v3.1"],
    ["v4.0", "CVSS v4.0"],
    ["CVSS_V3", "CVSS v3"],
    ["", "CVSS"],
  ])("labels version %j as %s", (version, label) => {
    expect(cvssVersionLabel(version)).toBe(label);
  });
});

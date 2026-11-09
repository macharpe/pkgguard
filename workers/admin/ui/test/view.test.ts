import { ENABLED_ECOSYSTEMS } from "@pkgguard/core/ecosystems";
import { describe, expect, it } from "vitest";
import type { DetectionRow, EnforcementInfo, RefreshRunInfo } from "../../src/api-types.js";
import { STALE_AFTER_MS, TABS, detectionExplanation, enforcementView, indexView, isDetectionView, parseTabHash, prefillFromDetection, prefillFromLookup, prefillSummary, sourceLabel, tabHash, viewVerdicts } from "../src/view.js";

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

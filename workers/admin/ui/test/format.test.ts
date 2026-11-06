import { describe, expect, it } from "vitest";
import { formatCount, formatDuration, isActive, kindLabel, osvUrl, parseVersionsInput, plural, referenceFilter, runDuration, runSummary, triggerLabel, versionsLabel, packageLabel, relativeTime, simulationLabel, splitIds, verdictBadge } from "../src/format.js";

const NOW = Date.parse("2026-11-06T12:00:00Z");
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();

describe("relativeTime", () => {
  it.each([
    [0, "just now"],
    [44, "just now"],
    [45, "1m ago"],
    [90, "2m ago"],
    [59 * 60, "59m ago"],
    [3600, "1h ago"],
    [23 * 3600, "23h ago"],
    [24 * 3600, "1d ago"],
    [29 * 86400, "29d ago"],
  ])("%d seconds ago reads %j", (seconds, expected) => {
    expect(relativeTime(ago(seconds), NOW)).toBe(expected);
  });
  it("shows a date after a month", () => {
    expect(relativeTime("2026-09-01T00:00:00Z", NOW)).toBe("2026-09-01");
  });
  it("treats the future as just now, so clock skew never prints a negative", () => {
    expect(relativeTime(ago(-600), NOW)).toBe("just now");
  });
  it("does not throw on garbage", () => {
    expect(relativeTime("not a date", NOW)).toBe("unknown");
    expect(relativeTime("", NOW)).toBe("unknown");
  });
});

describe("formatCount", () => {
  it("groups thousands", () => {
    expect(formatCount(0)).toBe("0");
    expect(formatCount(223662)).toBe("223,662");
  });
});

describe("osvUrl", () => {
  it("links to osv.dev and encodes the id", () => {
    expect(osvUrl("GHSA-mh6f-8j2x-4483")).toBe("https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483");
    expect(osvUrl("a/b?c#d")).toBe("https://osv.dev/vulnerability/a%2Fb%3Fc%23d");
  });
});

describe("splitIds / packageLabel", () => {
  it("splits, trims and drops empties", () => {
    expect(splitIds("A, B ,,C")).toEqual(["A", "B", "C"]);
    expect(splitIds(null)).toEqual([]);
    expect(splitIds("")).toEqual([]);
  });
  it("omits a missing version", () => {
    expect(packageLabel("lodash", "4.17.20")).toBe("lodash@4.17.20");
    expect(packageLabel("lodash", null)).toBe("lodash");
    expect(packageLabel("lodash", "")).toBe("lodash");
  });
});

describe("verdicts", () => {
  it("gives every verdict a distinct label and a colour", () => {
    const verdicts = ["blocked", "flagged", "allowed", "error"] as const;
    expect(new Set(verdicts.map((v) => verdictBadge(v).label)).size).toBe(4);
    expect(verdictBadge("blocked").colour).toBe("red");
    expect(verdictBadge("allowed").colour).toBe("green");
  });
  it("describes the policy, not the action, in the simulation", () => {
    expect(simulationLabel("blocked")).toBe("Would be blocked");
    expect(simulationLabel("flagged")).toBe("Would be flagged");
    expect(simulationLabel("allowed")).toBe("Would be allowed");
    expect(simulationLabel("error")).toBe("Index entry unreadable");
  });
});

describe("plural", () => {
  it("says 1 vulnerability, not 1 vulnerabilities", () => {
    expect(plural(1, "vulnerability", "vulnerabilities")).toBe("1 vulnerability");
    expect(plural(0, "vulnerability", "vulnerabilities")).toBe("0 vulnerabilities");
    expect(plural(3, "vulnerability", "vulnerabilities")).toBe("3 vulnerabilities");
  });
  it("defaults to adding an s and groups large counts", () => {
    expect(plural(2, "package")).toBe("2 packages");
    expect(plural(1234, "package")).toBe("1,234 packages");
  });
});

describe("formatDuration", () => {
  it.each([[0, "0s"], [44.4, "44s"], [59.6, "1m 00s"], [60, "1m 00s"], [200, "3m 20s"], [3599, "59m 59s"], [3600, "1h 00m"], [3900, "1h 05m"], [-5, "0s"]])("%d seconds reads %j", (s, expected) => {
    expect(formatDuration(s)).toBe(expected);
  });
});

describe("runDuration", () => {
  it("is the time between start and finish, and null while running or on bad data", () => {
    expect(runDuration({ started_at: "2026-11-07T00:00:00Z", finished_at: "2026-11-07T00:03:20Z" })).toBe(200);
    expect(runDuration({ started_at: "2026-11-07T00:00:00Z", finished_at: null })).toBeNull();
    expect(runDuration({ started_at: "garbage", finished_at: "2026-11-07T00:03:20Z" })).toBeNull();
    expect(runDuration({ started_at: "2026-11-07T00:03:20Z", finished_at: "2026-11-07T00:00:00Z" })).toBeNull();
  });
});

describe("isActive", () => {
  it("is true only for queued and running", () => {
    expect(isActive({ status: "queued" })).toBe(true);
    expect(isActive({ status: "running" })).toBe(true);
    expect(isActive({ status: "complete" })).toBe(false);
    expect(isActive({ status: "failed" })).toBe(false);
    expect(isActive(null)).toBe(false);
    expect(isActive(undefined)).toBe(false);
  });
});

describe("kindLabel / triggerLabel", () => {
  it("labels every kind", () => {
    expect([kindLabel("manual"), kindLabel("daily"), kindLabel("monthly")]).toEqual(["Manual", "Daily", "Monthly"]);
  });
  it("shows people as their email and machines as what they are", () => {
    expect(triggerLabel("cron")).toBe("Scheduled");
    expect(triggerLabel("service-token:abc.access")).toBe("Service token");
    expect(triggerLabel("ops@example.com")).toBe("ops@example.com");
  });
});

describe("runSummary", () => {
  const base = { status: "complete" as const, added: 13, updated: 4, removed: 0, errors: 0, error_detail: null };
  it("summarises a clean run", () => {
    expect(runSummary(base)).toBe("13 added · 4 updated");
  });
  it("mentions withdrawn records and records to retry only when there are some", () => {
    expect(runSummary({ ...base, removed: 2, errors: 3 })).toBe("13 added · 4 updated · 2 withdrawn · 3 to retry");
    expect(runSummary({ ...base, added: 1234 })).toBe("1,234 added · 4 updated");
  });
  it("shows the reason for a failure, or a plain Failed without one", () => {
    expect(runSummary({ ...base, status: "failed", error_detail: "no sync state for npm" })).toBe("no sync state for npm");
    expect(runSummary({ ...base, status: "failed" })).toBe("Failed");
  });
  it("says in progress for an unfinished run", () => {
    expect(runSummary({ ...base, status: "running" as never })).toBe("In progress");
  });
});

describe("parseVersionsInput", () => {
  it("splits on commas and whitespace, de-duplicates, and keeps order", () => {
    expect(parseVersionsInput("1.0.0, 1.0.1  2.0.0,\n1.0.0")).toEqual(["1.0.0", "1.0.1", "2.0.0"]);
  });
  it("means every version when blank", () => {
    expect(parseVersionsInput("")).toBeUndefined();
    expect(parseVersionsInput("  , ,\n")).toBeUndefined();
  });
});

describe("versionsLabel", () => {
  it("says all versions for null, lists a few, and counts the rest", () => {
    expect(versionsLabel(null)).toBe("All versions");
    expect(versionsLabel(["1.0.0"])).toBe("1.0.0");
    expect(versionsLabel(["1", "2", "3"])).toBe("1, 2, 3");
    expect(versionsLabel(["1", "2", "3", "4", "5"])).toBe("1, 2, 3 +2 more");
  });
});

describe("referenceFilter", () => {
  it("treats blank input as no filter", () => {
    expect(referenceFilter("")).toEqual({ state: "empty" });
    expect(referenceFilter("   ")).toEqual({ state: "empty" });
  });
  it("accepts a complete reference in any case and with stray spaces, and normalises it", () => {
    expect(referenceFilter("PG-7Q2K4M")).toEqual({ state: "valid", value: "PG-7Q2K4M" });
    expect(referenceFilter(" pg-7q2k4m ")).toEqual({ state: "valid", value: "PG-7Q2K4M" });
  });
  it.each(["P", "PG-", "PG-7Q2K4", "PG-7Q2K4MM", "7Q2K4M", "PG-7Q2K4I", "PG-7Q2K4O", "XX-7Q2K4M", "PG 7Q2K4M"])(
    "waits, without querying, while %s is not a full reference",
    (text) => expect(referenceFilter(text)).toEqual({ state: "partial" }),
  );
});

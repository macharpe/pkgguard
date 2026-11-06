import { describe, expect, it } from "vitest";
import { formatCount, osvUrl, plural, packageLabel, relativeTime, simulationLabel, splitIds, verdictBadge } from "../src/format.js";

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

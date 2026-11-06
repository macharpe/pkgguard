import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { evaluate } from "../src/osv/index-entry.js";
import { entryFromOsvRecords, osvQueryBody, parseOsvResponse } from "../src/osv/live.js";
import type { OsvRecord } from "../src/osv/types.js";

const fixture = (id: string): OsvRecord =>
  JSON.parse(readFileSync(new URL(`./fixtures/${id}.json`, import.meta.url), "utf8")) as OsvRecord;

describe("osvQueryBody", () => {
  it("queries by package, not by version, and uses OSV's ecosystem names", () => {
    expect(osvQueryBody("npm", "@Babel/Core")).toEqual({ package: { ecosystem: "npm", name: "@babel/core" } });
    expect(osvQueryBody("pypi", "Typing_Extensions")).toEqual({
      package: { ecosystem: "PyPI", name: "typing-extensions" },
    });
  });
});

describe("parseOsvResponse", () => {
  it("accepts an empty object as 'no vulnerabilities'", () => {
    expect(parseOsvResponse({})).toEqual({ records: [], complete: true });
  });
  it("is incomplete when OSV paginates", () => {
    const r = parseOsvResponse({ vulns: [fixture("GHSA-mh6f-8j2x-4483")], next_page_token: "x" });
    expect(r.records).toHaveLength(1);
    expect(r.complete).toBe(false);
  });
  it("drops malformed records and reports incomplete rather than guessing", () => {
    const r = parseOsvResponse({ vulns: [fixture("GHSA-mh6f-8j2x-4483"), { id: 5 }, null, "x"] });
    expect(r.records).toHaveLength(1);
    expect(r.complete).toBe(false);
  });
  it.each([[null], [undefined], [3], ["x"], [[]], [{ vulns: "x" }], [{ vulns: {} }]])("treats %j as incomplete and empty", (body) => {
    expect(parseOsvResponse(body)).toEqual({ records: [], complete: false });
  });
});

describe("entryFromOsvRecords", () => {
  it("builds an entry that evaluates event-stream@3.3.6 as malware", () => {
    const entry = entryFromOsvRecords("npm", "event-stream", [fixture("GHSA-mh6f-8j2x-4483")], "t");
    expect(entry).not.toBeNull();
    expect(evaluate("npm", entry!, "3.3.6").malware).toEqual(["GHSA-mh6f-8j2x-4483"]);
    expect(evaluate("npm", entry!, "3.3.5").malware).toEqual([]);
  });
  it("keeps only the requested package from a multi-package record", () => {
    const entry = entryFromOsvRecords("npm", "flatmap-stream", [fixture("GHSA-mh6f-8j2x-4483")], "t");
    expect(entry?.m).toHaveLength(1);
    const other = entryFromOsvRecords("npm", "event-stream", [fixture("GHSA-mh6f-8j2x-4483")], "t");
    expect(other?.m).toHaveLength(1);
  });
  it("normalizes the name it matches on", () => {
    expect(entryFromOsvRecords("npm", "Event-Stream", [fixture("GHSA-mh6f-8j2x-4483")], "t")).not.toBeNull();
  });
  it("returns null when no record applies to the package", () => {
    expect(entryFromOsvRecords("npm", "left-pad", [fixture("GHSA-mh6f-8j2x-4483")], "t")).toBeNull();
    expect(entryFromOsvRecords("npm", "event-stream", [], "t")).toBeNull();
  });
  it("does not leak an advisory across ecosystems", () => {
    expect(entryFromOsvRecords("pypi", "event-stream", [fixture("GHSA-mh6f-8j2x-4483")], "t")).toBeNull();
  });
  it("classifies a CVE-only record as a vulnerability, not malware", () => {
    const entry = entryFromOsvRecords("npm", "ua-parser-js", [fixture("GHSA-394c-5j6w-4xmx")], "t");
    expect(entry?.m).toEqual([]);
    expect(entry?.c.length).toBeGreaterThan(0);
  });
});

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { distill } from "../src/osv/distill.js";
import { buildKvEntry, evaluate, summarizeVerdict, type KvEntry } from "../src/osv/index-entry.js";
import type { OsvRecord } from "../src/osv/types.js";

function fixture(id: string): OsvRecord {
  return JSON.parse(readFileSync(new URL(`./fixtures/${id}.json`, import.meta.url), "utf8")) as OsvRecord;
}

function entryFor(id: string, ecosystem: "npm" | "pypi", name: string): KvEntry {
  const rows = distill(fixture(id)).filter((r) => r.ecosystem === ecosystem && r.packageName === name);
  const entry = buildKvEntry(rows, "2026-11-06T00:00:00Z");
  if (!entry) throw new Error(`no entry for ${name}`);
  return entry;
}

describe("distill — structure", () => {
  it("emits one row per affected package, in scope only", () => {
    const rows = distill(fixture("GHSA-35jh-r3h4-6jhm"));
    expect(rows.map((r) => r.packageName).sort()).toEqual(["lodash", "lodash-es", "lodash-template", "lodash.template"]);
    expect(rows.every((r) => r.ecosystem === "npm")).toBe(true);
  });
  it("one record affecting two packages yields two rows (event-stream + flatmap-stream)", () => {
    const rows = distill(fixture("GHSA-mh6f-8j2x-4483"));
    expect(rows.map((r) => r.packageName).sort()).toEqual(["event-stream", "flatmap-stream"]);
    expect(rows.every((r) => r.kind === "malware")).toBe(true);
  });
  it("merges many affected[] entries for one package (coa)", () => {
    const rows = distill(fixture("GHSA-73qr-pfmq-6rp8"));
    expect(rows).toHaveLength(1);
    expect(rows[0]!.spec.v.length).toBeGreaterThan(5);
    expect(rows[0]!.spec.v).toContain("2.0.3");
  });
  it("scoped npm name keeps its scope and exposes a namespace", () => {
    const [row] = distill(fixture("MAL-2024-11183"));
    expect(row).toMatchObject({ packageName: "@solana/web3.js", namespace: "@solana", kind: "malware" });
  });
  it("carries severity and CWE ids", () => {
    const [row] = distill(fixture("GHSA-394c-5j6w-4xmx"));
    expect(row).toMatchObject({ severity: "HIGH", cweIds: ["CWE-400"], kind: "vulnerability" });
  });
  it("PyPI names are PEP 503 normalized", () => {
    const record: OsvRecord = {
      id: "GHSA-test",
      modified: "2026-01-01T00:00:00Z",
      affected: [{ package: { ecosystem: "PyPI", name: "Typing_Extensions" }, versions: ["1.0"] }],
    };
    expect(distill(record)[0]!.packageName).toBe("typing-extensions");
  });
  it("drops GIT ranges and skips out-of-scope or nameless entries", () => {
    const record: OsvRecord = {
      id: "GHSA-test",
      modified: "2026-01-01T00:00:00Z",
      affected: [
        { package: { ecosystem: "npm", name: "a" }, ranges: [{ type: "GIT", events: [{ introduced: "abc" }] }] },
        { package: { ecosystem: "Go", name: "b" }, versions: ["1.0.0"] },
        { package: { ecosystem: "npm", name: "" }, versions: ["1.0.0"] },
        {},
      ],
    };
    const rows = distill(record);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.spec).toEqual({ r: [], v: [] });
  });
  it("a malware entry with no ranges or versions means every version", () => {
    const record: OsvRecord = {
      id: "MAL-2026-9",
      modified: "2026-01-01T00:00:00Z",
      affected: [{ package: { ecosystem: "npm", name: "evil" } }],
    };
    expect(distill(record)[0]!.spec.all).toBe(true);
  });
  it("a vulnerability entry with no ranges or versions affects nothing", () => {
    const record: OsvRecord = {
      id: "GHSA-test",
      modified: "2026-01-01T00:00:00Z",
      affected: [{ package: { ecosystem: "npm", name: "meh" } }],
    };
    expect(distill(record)[0]!.spec.all).toBeUndefined();
  });
  it("tolerates a record with no affected[]", () => {
    expect(distill({ id: "X", modified: "" })).toEqual([]);
  });
});

describe("evaluate — end to end on real OSV records", () => {
  it("event-stream: only 3.3.6 up to 4.0.0 is malware; the flagship demo case", () => {
    const entry = entryFor("GHSA-mh6f-8j2x-4483", "npm", "event-stream");
    expect(evaluate("npm", entry, "3.3.6").malware).toEqual(["GHSA-mh6f-8j2x-4483"]);
    expect(evaluate("npm", entry, "3.3.5").malware).toEqual([]);
    expect(evaluate("npm", entry, "4.0.0").malware).toEqual([]);
  });
  it("flatmap-stream: every version is malware", () => {
    const entry = entryFor("GHSA-mh6f-8j2x-4483", "npm", "flatmap-stream");
    expect(evaluate("npm", entry, "0.1.1").malware).toHaveLength(1);
    expect(evaluate("npm", entry, "0.1.2").malware).toHaveLength(1);
  });
  it("coa: listed versions only", () => {
    const entry = entryFor("GHSA-73qr-pfmq-6rp8", "npm", "coa");
    expect(evaluate("npm", entry, "2.0.3").malware).toHaveLength(1);
    expect(evaluate("npm", entry, "2.0.2").malware).toHaveLength(0);
  });
  it("ctx on PyPI: last_affected 0.1.4 is inclusive", () => {
    const entry = entryFor("GHSA-4g82-3jcr-q52w", "pypi", "ctx");
    expect(evaluate("pypi", entry, "0.1.2").malware).toHaveLength(1);
    expect(evaluate("pypi", entry, "0.1.4").malware).toHaveLength(1);
    expect(evaluate("pypi", entry, "0.1.5").malware).toHaveLength(0);
  });
  it("@solana/web3.js: 1.95.6 and 1.95.7 only", () => {
    const entry = entryFor("MAL-2024-11183", "npm", "@solana/web3.js");
    expect(evaluate("npm", entry, "1.95.5").malware).toHaveLength(0);
    expect(evaluate("npm", entry, "1.95.6").malware).toHaveLength(1);
    expect(evaluate("npm", entry, "1.95.7").malware).toHaveLength(1);
    expect(evaluate("npm", entry, "1.95.8").malware).toHaveLength(0);
  });
  it("node-ipc: listed MAL versions only", () => {
    const entry = entryFor("MAL-2026-3744", "npm", "node-ipc");
    expect(evaluate("npm", entry, "9.1.6").malware).toEqual(["MAL-2026-3744"]);
    expect(evaluate("npm", entry, "9.1.7").malware).toEqual([]);
  });
  it("ua-parser-js: a vulnerability, never malware — negative control", () => {
    const entry = entryFor("GHSA-394c-5j6w-4xmx", "npm", "ua-parser-js");
    const verdict = evaluate("npm", entry, "0.7.22");
    expect(verdict.malware).toEqual([]);
    expect(verdict.vulnerabilities).toEqual([{ id: "GHSA-394c-5j6w-4xmx", severity: "HIGH" }]);
    expect(evaluate("npm", entry, "0.7.23").vulnerabilities).toEqual([]);
  });
  it("lodash: affected below 4.17.21, clean at and above", () => {
    const entry = entryFor("GHSA-35jh-r3h4-6jhm", "npm", "lodash");
    expect(evaluate("npm", entry, "4.17.20").vulnerabilities).toHaveLength(1);
    expect(evaluate("npm", entry, "4.17.21").vulnerabilities).toHaveLength(0);
  });
  it("lodash.template uses last_affected", () => {
    const entry = entryFor("GHSA-35jh-r3h4-6jhm", "npm", "lodash.template");
    expect(evaluate("npm", entry, "4.5.0").vulnerabilities).toHaveLength(1);
    expect(evaluate("npm", entry, "4.5.1").vulnerabilities).toHaveLength(0);
  });
  it("an unparseable version never matches a range", () => {
    const entry = entryFor("GHSA-394c-5j6w-4xmx", "npm", "ua-parser-js");
    expect(evaluate("npm", entry, "not-a-version")).toEqual({ malware: [], vulnerabilities: [] });
  });
});

describe("buildKvEntry", () => {
  it("excludes withdrawn advisories and returns null when nothing remains", () => {
    const record: OsvRecord = {
      id: "MAL-2026-1",
      modified: "2026-01-01T00:00:00Z",
      withdrawn: "2026-02-01T00:00:00Z",
      affected: [{ package: { ecosystem: "npm", name: "x" }, versions: ["1.0.0"] }],
    };
    expect(distill(record)[0]!.withdrawn).toBe(true);
    expect(buildKvEntry(distill(record), "t")).toBeNull();
  });
  it("splits malware and vulnerabilities and sorts deterministically", () => {
    const rows = [
      ...distill({ id: "GHSA-b", modified: "", affected: [{ package: { ecosystem: "npm", name: "x" }, versions: ["1"] }] }),
      ...distill({ id: "GHSA-a", modified: "", affected: [{ package: { ecosystem: "npm", name: "x" }, versions: ["1"] }] }),
      ...distill({ id: "MAL-1", modified: "", affected: [{ package: { ecosystem: "npm", name: "x" }, versions: ["1"] }] }),
    ];
    const entry = buildKvEntry(rows, "t")!;
    expect(entry.m.map((a) => a.id)).toEqual(["MAL-1"]);
    expect(entry.c.map((a) => a.id)).toEqual(["GHSA-a", "GHSA-b"]);
  });
  it("round-trips through JSON, as it does through KV", () => {
    const entry = entryFor("GHSA-mh6f-8j2x-4483", "npm", "event-stream");
    const revived = JSON.parse(JSON.stringify(entry)) as KvEntry;
    expect(evaluate("npm", revived, "3.3.6").malware).toHaveLength(1);
  });
});

describe("summarizeVerdict", () => {
  it("blocks on malware, and malware outranks vulnerabilities", () => {
    expect(summarizeVerdict({ malware: ["MAL-1"], vulnerabilities: [{ id: "CVE-1", severity: "HIGH" }] })).toEqual({
      outcome: "blocked",
      reason: "osv-malware",
      osvIds: ["MAL-1"],
    });
  });
  it("flags vulnerabilities without blocking", () => {
    expect(summarizeVerdict({ malware: [], vulnerabilities: [{ id: "A", severity: null }, { id: "B", severity: "LOW" }] })).toEqual({
      outcome: "flagged",
      reason: "osv-cve",
      osvIds: ["A", "B"],
    });
  });
  it("allows when nothing matches", () => {
    expect(summarizeVerdict({ malware: [], vulnerabilities: [] })).toEqual({ outcome: "allowed", reason: null, osvIds: [] });
  });
});

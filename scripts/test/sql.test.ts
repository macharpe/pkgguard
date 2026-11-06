import { describe, expect, it } from "vitest";
import type { Advisory } from "../../packages/core/src/index.js";
import { advisoryInsert, chunk, sqlString, syncStateInsert } from "../lib/sql.js";

const advisory: Advisory = {
  ecosystem: "npm",
  osvId: "GHSA-mh6f-8j2x-4483",
  packageName: "event-stream",
  namespace: null,
  kind: "malware",
  severity: "CRITICAL",
  summary: "It's a trap",
  cweIds: ["CWE-506"],
  spec: { r: [[{ introduced: "3.3.6" }, { fixed: "4.0.0" }]], v: ["3.3.6"] },
  withdrawn: false,
  modified: "2020-06-16T21:46:17Z",
};

describe("sqlString", () => {
  it("doubles single quotes", () => {
    expect(sqlString("it's")).toBe("'it''s'");
  });
  it("strips NUL bytes", () => {
    expect(sqlString("a\u0000b")).toBe("'ab'");
  });
  it("renders null", () => {
    expect(sqlString(null)).toBe("NULL");
  });
  it("neutralises a statement-terminating injection attempt", () => {
    expect(sqlString("x'; DROP TABLE advisories; --")).toBe("'x''; DROP TABLE advisories; --'");
  });
  it("keeps newlines and unicode", () => {
    expect(sqlString("a\nb ✓")).toBe("'a\nb ✓'");
  });
});

describe("advisoryInsert", () => {
  it("produces one INSERT OR REPLACE with all eleven columns", () => {
    const sql = advisoryInsert(advisory);
    expect(sql.startsWith("INSERT OR REPLACE INTO advisories")).toBe(true);
    expect(sql.endsWith(");")).toBe(true);
    expect(sql).toContain("'It''s a trap'");
    expect(sql).toContain("'CWE-506'");
    expect(sql).toContain(", 0, ");
    expect(sql.match(/\n/g)).toBeNull();
  });
  it("serialises the spec as JSON that round-trips", () => {
    const sql = advisoryInsert(advisory);
    const json = /'(\{"r":.*?\})'/.exec(sql)?.[1]?.replaceAll("''", "'");
    expect(JSON.parse(json ?? "")).toEqual(advisory.spec);
  });
  it("truncates long summaries and writes NULLs", () => {
    const sql = advisoryInsert({ ...advisory, summary: "x".repeat(2000), severity: null, namespace: null, cweIds: [] });
    expect(sql).not.toContain("x".repeat(501));
    expect(sql).toContain("NULL");
  });
  it("marks withdrawn rows", () => {
    expect(advisoryInsert({ ...advisory, withdrawn: true })).toMatch(/, 1, '2020/);
  });
});

describe("syncStateInsert / chunk", () => {
  it("builds the sync_state upsert", () => {
    expect(syncStateInsert("npm", "2026-01-01T00:00:00Z", 5, "t")).toContain("VALUES ('npm', '2026-01-01T00:00:00Z', 5, 't')");
  });
  it("chunks evenly and keeps the remainder", () => {
    expect([...chunk([1, 2, 3, 4, 5], 2)]).toEqual([[1, 2], [3, 4], [5]]);
    expect([...chunk([], 3)]).toEqual([]);
  });
});

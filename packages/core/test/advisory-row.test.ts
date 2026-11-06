import { describe, expect, it } from "vitest";
import { ADVISORY_COLUMNS, advisoryFromRow, advisoryRow } from "../src/osv/advisory-row.js";
import type { Advisory } from "../src/osv/distill.js";

const base: Advisory = {
  ecosystem: "npm",
  osvId: "GHSA-mh6f-8j2x-4483",
  packageName: "event-stream",
  namespace: null,
  kind: "malware",
  severity: "CRITICAL",
  summary: "It's a trap",
  cweIds: ["CWE-506", "CWE-507"],
  spec: { r: [[{ introduced: "3.3.6" }, { fixed: "4.0.0" }]], v: ["3.3.6"], all: true },
  withdrawn: false,
  modified: "2020-06-16T21:46:17Z",
};
const asRecord = (a: Advisory): Record<string, unknown> => Object.fromEntries(ADVISORY_COLUMNS.map((c, i) => [c, advisoryRow(a)[i]]));

describe("advisoryRow", () => {
  it("has one value per column, in column order", () => {
    expect(advisoryRow(base)).toHaveLength(ADVISORY_COLUMNS.length);
    expect(asRecord(base)).toMatchObject({ ecosystem: "npm", osv_id: "GHSA-mh6f-8j2x-4483", package_name: "event-stream", kind: "malware", withdrawn: 0, cwe_ids: "CWE-506,CWE-507" });
  });
  it("stores nulls for absent optional fields", () => {
    const r = asRecord({ ...base, namespace: null, severity: null, summary: null, cweIds: [] });
    expect(r).toMatchObject({ namespace: null, severity: null, summary: null, cwe_ids: null });
  });
  it("truncates a long summary to 500 characters", () => {
    expect((asRecord({ ...base, summary: "x".repeat(900) })["summary"] as string).length).toBe(500);
  });
  it("strips NUL from every string, so no write path can carry one into the table", () => {
    const r = advisoryRow({ ...base, osvId: "A\u0000B", packageName: "p\u0000q", summary: "s\u0000t", namespace: "@n\u0000s", cweIds: ["C\u0000W"], spec: { r: [], v: ["1\u0000.0"] } });
    for (const v of r) if (typeof v === "string") expect(v).not.toContain("\u0000");
  });
  it("encodes withdrawn as 1", () => {
    expect(asRecord({ ...base, withdrawn: true })["withdrawn"]).toBe(1);
  });
});

describe("advisoryFromRow", () => {
  it("round-trips an advisory", () => {
    expect(advisoryFromRow(asRecord(base))).toEqual(base);
  });
  it("round-trips optional fields as null and empty", () => {
    const a: Advisory = { ...base, namespace: null, severity: null, summary: null, cweIds: [], withdrawn: true, spec: { r: [], v: [] } };
    expect(advisoryFromRow(asRecord(a))).toEqual(a);
  });
  it.each([
    ["unknown ecosystem", { ecosystem: "gem" }],
    ["unknown kind", { kind: "weird" }],
    ["missing osv_id", { osv_id: null }],
    ["missing package_name", { package_name: 5 }],
    ["missing modified", { modified: undefined }],
    ["ranges_json not a string", { ranges_json: { r: [], v: [] } }],
    ["ranges_json not JSON", { ranges_json: "{nope" }],
    ["ranges_json wrong shape", { ranges_json: '{"x":1}' }],
    ["ranges_json null", { ranges_json: "null" }],
    ["ranges_json array", { ranges_json: "[]" }],
  ])("rejects a row with %s, returning null rather than throwing", (_n, over) => {
    expect(advisoryFromRow({ ...asRecord(base), ...over })).toBeNull();
  });
});

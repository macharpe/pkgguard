import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  chooseCvssRating,
  distillRated,
  distillRatedFor,
  rateCandidate,
  ratingFor,
  recordRatings,
  scoreCvssVector,
} from "../src/cvss.js";
import { ADVISORY_COLUMNS, advisoryFromRow, advisoryRow } from "../src/osv/advisory-row.js";
import { CVSS_SOURCE_AFFECTED, CVSS_SOURCE_RECORD, cvssLabel, parseCvssRating, type CvssRating } from "../src/osv/cvss-rating.js";
import { distill } from "../src/osv/distill.js";
import type { OsvRecord } from "../src/osv/types.js";

const fixture = (id: string): OsvRecord => JSON.parse(readFileSync(new URL(`./fixtures/${id}.json`, import.meta.url), "utf8")) as OsvRecord;

const V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
const V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
const rating = (score: number, version: string, vector: string, source = CVSS_SOURCE_RECORD): CvssRating => ({ score, version, vector, source });

describe("scoreCvssVector — supported versions", () => {
  it.each([
    [V31, 9.8, "3.1"],
    [V30, 10, "3.0"],
    [V40, 9.3, "4.0"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "3.1"],
    ["CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8, "3.1"],
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "3.0"],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, "3.1"],
    ["CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0, "4.0"],
  ])("%s scores %s", (vector, score, version) => {
    expect(scoreCvssVector(vector)).toEqual({ score, version });
  });
  it("scores the base metrics only: temporal and environmental metrics never move the rating", () => {
    expect(scoreCvssVector(`${V31}/E:F/RL:O/RC:C`)?.score).toBe(9.8);
    expect(scoreCvssVector(`${V31}/MAV:L/CR:H`)?.score).toBe(9.8);
    expect(scoreCvssVector(`${V40}/E:P`)?.score).toBe(9.3);
    expect(scoreCvssVector(`${V40}/MAV:L/CR:H`)?.score).toBe(9.3);
  });
});

describe("scoreCvssVector — refusals", () => {
  it.each([
    ["not a string", 5],
    ["null", null],
    ["empty", ""],
    ["garbage", "garbage"],
    ["no prefix (CVSS v2 style)", "AV:N/AC:L/Au:N/C:P/I:P/A:P"],
    ["unsupported prefix 3.2", "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["leading space", ` ${V31}`],
    ["trailing slash", `${V31}/`],
    ["missing base metric", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"],
    ["missing v4 base metric", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"],
    ["duplicate metric", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["duplicate identical metric", "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["unknown metric", `${V31}/ZZ:1`],
    ["metric of another version", `${V31}/AT:N`],
    ["invalid metric value", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["undefined (X) base value", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X"],
    ["undefined (X) v4 base value", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:X"],
    ["invalid temporal value", `${V31}/E:Q`],
    ["lowercase value", "CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["spelled-out value", "CVSS:3.1/AV:Network/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["spelled-out environmental value", `${V31}/MAV:Network`],
    ["part without a value", `${V31}/E`],
    ["empty part", `${V31}//E:F`],
    ["over-long", `${V31}/${"E:F/".repeat(200)}`],
  ])("refuses %s", (_name, vector) => {
    expect(scoreCvssVector(vector)).toBeNull();
  });
});

describe("rateCandidate", () => {
  it("rates a CVSS_V3 and a CVSS_V4 candidate, keeping the vector and source verbatim", () => {
    expect(rateCandidate({ type: "CVSS_V3", score: V31, source: "s" })).toEqual({ score: 9.8, version: "3.1", vector: V31, source: "s" });
    expect(rateCandidate({ type: "CVSS_V3", score: V30, source: "s" })).toMatchObject({ score: 10, version: "3.0" });
    expect(rateCandidate({ type: "CVSS_V4", score: V40, source: "s" })).toMatchObject({ score: 9.3, version: "4.0" });
  });
  it.each([
    ["CVSS_V2", "AV:N/AC:L/Au:N/C:P/I:P/A:P"],
    ["Ubuntu", "high"],
    ["constructor", V31],
    ["__proto__", V31],
    ["toString", V31],
    ["CVSS_V3", V40],
    ["CVSS_V4", V31],
    ["cvss_v3", V31],
    ["CVSS_V3", "9.8"],
  ])("refuses type %s with %s", (type, score) => {
    expect(rateCandidate({ type, score, source: "s" })).toBeNull();
  });
  it("refuses non-string fields at runtime", () => {
    expect(rateCandidate({ type: 3, score: V31, source: "s" } as never)).toBeNull();
    expect(rateCandidate({ type: "CVSS_V3", score: 9.8, source: "s" } as never)).toBeNull();
  });
});

describe("chooseCvssRating", () => {
  it("is null for none", () => expect(chooseCvssRating([])).toBeNull());
  it("takes the highest score", () => {
    const a = rating(5.3, "3.1", "a");
    const b = rating(9.3, "4.0", "b");
    expect(chooseCvssRating([a, b])).toBe(b);
    expect(chooseCvssRating([b, a])).toBe(b);
  });
  it("breaks a tie by newest version, then vector text, then source, whatever the input order", () => {
    const v31 = rating(9.8, "3.1", "CVSS:3.1/x");
    const v40 = rating(9.8, "4.0", "CVSS:4.0/x");
    const v31b = rating(9.8, "3.1", "CVSS:3.1/y");
    const s1 = rating(9.8, "3.1", "CVSS:3.1/x", "a");
    const s2 = rating(9.8, "3.1", "CVSS:3.1/x", "b");
    for (const order of [[v31, v40], [v40, v31]]) expect(chooseCvssRating(order)).toBe(v40);
    for (const order of [[v31, v31b], [v31b, v31]]) expect(chooseCvssRating(order)).toBe(v31);
    for (const order of [[s1, s2], [s2, s1]]) expect(chooseCvssRating(order)).toBe(s1);
  });
});

describe("cvssLabel boundaries", () => {
  it.each([
    [0, "none"],
    [0.1, "low"],
    [3.9, "low"],
    [4, "medium"],
    [6.9, "medium"],
    [7, "high"],
    [8.9, "high"],
    [9, "critical"],
    [10, "critical"],
  ])("%s is %s", (score, label) => expect(cvssLabel(score)).toBe(label));
  it.each([[-0.1], [10.1], [Number.NaN], [Infinity], ["5"], [null]])("%s is not a score", (v) => expect(cvssLabel(v as number)).toBeNull());
});

describe("parseCvssRating", () => {
  const good = rating(9.8, "3.1", V31);
  it("accepts an object and its JSON text, and drops extra properties", () => {
    expect(parseCvssRating(good)).toEqual(good);
    expect(parseCvssRating(JSON.stringify(good))).toEqual(good);
    expect(parseCvssRating({ ...good, extra: 1 })).toEqual(good);
  });
  it("accepts a zero score", () => expect(parseCvssRating({ ...good, score: 0 })?.score).toBe(0));
  it.each([
    ["null", null],
    ["undefined", undefined],
    ["a number", 9.8],
    ["an array", [good]],
    ["not JSON", "{nope"],
    ["JSON null", "null"],
    ["score as string", { ...good, score: "9.8" }],
    ["score above 10", { ...good, score: 10.1 }],
    ["negative score", { ...good, score: -1 }],
    ["NaN score", { ...good, score: Number.NaN }],
    ["unsupported version", { ...good, version: "2.0" }],
    ["version as number", { ...good, version: 3.1 }],
    ["vector of another version", { ...good, vector: V40 }],
    ["vector without prefix", { ...good, vector: "AV:N" }],
    ["empty vector", { ...good, vector: "" }],
    ["over-long vector", { ...good, vector: `${V31}/${"x".repeat(600)}` }],
    ["missing source", { ...good, source: undefined }],
    ["empty source", { ...good, source: "" }],
    ["over-long source", { ...good, source: "s".repeat(65) }],
  ])("rejects %s", (_n, value) => expect(parseCvssRating(value)).toBeNull());
});

const record = (over: Partial<OsvRecord>): OsvRecord => ({
  id: "GHSA-test-0001",
  modified: "2026-01-01T00:00:00Z",
  summary: "x",
  affected: [{ package: { ecosystem: "npm", name: "alpha" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }],
  ...over,
});

describe("distillRated", () => {
  it("rates a vulnerability from the record's top-level severity", () => {
    const [row] = distillRated(record({ severity: [{ type: "CVSS_V3", score: V31 }] }));
    expect(row!.cvss).toEqual({ score: 9.8, version: "3.1", vector: V31, source: CVSS_SOURCE_RECORD });
  });
  it("rates from affected[].severity with its own provenance", () => {
    const [row] = distillRated(
      record({ affected: [{ package: { ecosystem: "npm", name: "alpha" }, severity: [{ type: "CVSS_V4", score: V40 }], ranges: [] }] }),
    );
    expect(row!.cvss).toEqual({ score: 9.3, version: "4.0", vector: V40, source: CVSS_SOURCE_AFFECTED });
  });
  it("picks the highest across v3.0, v3.1 and v4, and across both places", () => {
    const [row] = distillRated(
      record({
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }, { type: "CVSS_V4", score: V40 }],
        affected: [{ package: { ecosystem: "npm", name: "alpha" }, severity: [{ type: "CVSS_V3", score: V30 }], ranges: [] }],
      }),
    );
    expect(row!.cvss).toMatchObject({ score: 10, version: "3.0", source: CVSS_SOURCE_AFFECTED });
  });
  it("skips invalid candidates and uses a valid one beside them", () => {
    const [row] = distillRated(
      record({
        severity: [
          { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
          { type: "CVSS_V2", score: "AV:N/AC:L/Au:N/C:C/I:C/A:C" },
          { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" },
          {},
        ],
      }),
    );
    expect(row!.cvss?.score).toBe(5.3);
  });
  it("leaves cvss off when no vector is valid, and keeps the categorical severity as it was", () => {
    const [row] = distillRated(record({ severity: [{ type: "CVSS_V3", score: "nope" }], database_specific: { severity: "high" } }));
    expect(row!.cvss).toBeUndefined();
    expect(row!.severity).toBe("HIGH");
  });
  it("never changes anything but cvss", () => {
    const r = record({ severity: [{ type: "CVSS_V3", score: V31 }], database_specific: { severity: "MODERATE" } });
    const { cvss, ...rest } = distillRated(r)[0]!;
    expect(cvss).toBeDefined();
    expect(rest).toEqual(distill(r)[0]);
  });
  it("never rates malware, even with a valid vector (event-stream is malware by CWE)", () => {
    const ev = fixture("GHSA-mh6f-8j2x-4483");
    const withSeverity: OsvRecord = { ...ev, severity: [{ type: "CVSS_V3", score: V31 }] };
    const rows = distillRated(withSeverity);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row.kind).toBe("malware");
      expect(row.cvss).toBeUndefined();
    }
  });
  it("rates a real fixture from its own vector", () => {
    const [row] = distillRated(fixture("cargo-RUSTSEC-2020-0071"));
    expect(row!.cvss).toMatchObject({ version: "3.1", vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", source: CVSS_SOURCE_RECORD });
    expect(row!.cvss!.score).toBe(6.2);
  });
});

describe("affected-scoped ratings do not leak across packages", () => {
  const two = record({
    affected: [
      { package: { ecosystem: "npm", name: "alpha" }, severity: [{ type: "CVSS_V3", score: V31 }], ranges: [] },
      { package: { ecosystem: "npm", name: "beta" }, severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }], ranges: [] },
      { package: { ecosystem: "npm", name: "gamma" }, ranges: [] },
    ],
  });
  it("gives each package only its own affected severity", () => {
    const rows = new Map(distillRated(two).map((r) => [r.packageName, r.cvss]));
    expect(rows.get("alpha")?.score).toBe(9.8);
    expect(rows.get("beta")?.score).toBe(5.3);
    expect(rows.get("gamma")).toBeUndefined();
  });
  it("applies a top-level rating to every package, but a package's own higher one wins only for that package", () => {
    const rows = new Map(
      distillRated({ ...two, severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" }] }).map((r) => [r.packageName, r.cvss?.score]),
    );
    expect(rows.get("alpha")).toBe(9.8);
    expect(rows.get("beta")).toBe(5.3);
    expect(rows.get("gamma")).toBe(1.8);
  });
  it("keys by normalized name, and by ecosystem", () => {
    const rec = record({
      affected: [
        { package: { ecosystem: "PyPI", name: "My_Pkg" }, severity: [{ type: "CVSS_V3", score: V31 }], ranges: [] },
        { package: { ecosystem: "npm", name: "My_Pkg" }, ranges: [] },
      ],
    });
    const rows = distillRatedFor(rec, ["npm", "pypi"]);
    expect(rows.find((r) => r.ecosystem === "pypi")?.cvss?.score).toBe(9.8);
    expect(rows.find((r) => r.ecosystem === "npm")?.cvss).toBeUndefined();
  });
  it("merges two affected[] entries for one package (same name, different ranges)", () => {
    const rec = record({
      affected: [
        { package: { ecosystem: "npm", name: "alpha" }, severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" }], ranges: [] },
        { package: { ecosystem: "npm", name: "alpha" }, severity: [{ type: "CVSS_V3", score: V31 }], ranges: [] },
      ],
    });
    expect(distillRated(rec)).toHaveLength(1);
    expect(distillRated(rec)[0]!.cvss?.score).toBe(9.8);
  });
  it("exposes the raw readers", () => {
    expect(recordRatings(record({ severity: [{ type: "CVSS_V3", score: V31 }] }))).toHaveLength(1);
    expect(ratingFor(two, () => false)).toBeNull();
  });
});

describe("storage round trip", () => {
  it("writes cvss_json last, and reads it back", () => {
    expect(ADVISORY_COLUMNS.at(-1)).toBe("cvss_json");
    const [row] = distillRated(fixture("cargo-RUSTSEC-2020-0071"));
    const values = advisoryRow(row!);
    expect(values).toHaveLength(ADVISORY_COLUMNS.length);
    expect(JSON.parse(values.at(-1) as string)).toEqual(row!.cvss);
    const asRecord = Object.fromEntries(ADVISORY_COLUMNS.map((c, i) => [c, values[i]]));
    expect(advisoryFromRow(asRecord)).toEqual(row);
  });
  it("stores null without a rating, and a corrupt stored value reads back as no rating, not as a failed row", () => {
    const [row] = distill(fixture("cargo-RUSTSEC-2020-0071"));
    expect(advisoryRow(row!).at(-1)).toBeNull();
    const asRecord = Object.fromEntries(ADVISORY_COLUMNS.map((c, i) => [c, advisoryRow(row!)[i]]));
    for (const bad of ["{nope", '{"score":99}', 5, null]) {
      const read = advisoryFromRow({ ...asRecord, cvss_json: bad });
      expect(read).not.toBeNull();
      expect(read!.cvss).toBeUndefined();
    }
  });
  it("a row from before the migration (no cvss_json) still reads", () => {
    const [row] = distill(fixture("cargo-RUSTSEC-2020-0071"));
    const asRecord = Object.fromEntries(ADVISORY_COLUMNS.map((c, i) => [c, advisoryRow(row!)[i]]));
    delete asRecord["cvss_json"];
    expect(advisoryFromRow(asRecord)).toEqual(row);
  });
});

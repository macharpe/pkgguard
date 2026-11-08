import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { Census, findings, formatCensus } from "../lib/census.js";

const FIXTURES = join(import.meta.dirname, "../../packages/core/test/fixtures");
const fixture = (name: string): unknown => JSON.parse(readFileSync(join(FIXTURES, name), "utf8"));
const rec = (id: string, ...affected: unknown[]) => ({ id, modified: "2026-11-06T00:00:00Z", affected });
const pkg = (ecosystem: string, name: string, extra: Record<string, unknown> = {}) => ({ package: { ecosystem, name }, ...extra });

describe("Census: what a feed would do", () => {
  it("counts range boundaries and listed versions apart, and leaves OSV's beginning of time alone", () => {
    const census = new Census("npm");
    census.add(rec("GHSA-1", pkg("npm", "x", { ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0" }] }], versions: ["2.0.0", "bad"] })));
    expect(census.report().boundaries).toEqual({ total: 1, rejected: 1, rejectedInMalware: 0, examples: ["1.0"] });
    expect(census.report().listed).toEqual({ total: 2, rejected: 1, examples: ["bad"] });
  });
  it("says how many unreadable boundaries sit in malware advisories", () => {
    const census = new Census("npm");
    census.add(rec("MAL-2026-1", pkg("npm", "evil", { ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0" }] }] })));
    census.add(rec("GHSA-2", pkg("npm", "vuln", { ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0" }] }] })));
    expect(census.report().boundaries).toMatchObject({ rejected: 2, rejectedInMalware: 1 });
  });
  it("reads each ecosystem with its own comparator", () => {
    const record = rec("GHSA-1", pkg("npm", "x", { versions: ["1.0a1"] }), pkg("PyPI", "y", { versions: ["1.0a1"] }));
    const npm = new Census("npm");
    const pypi = new Census("pypi");
    npm.add(record);
    pypi.add(record);
    expect(npm.report().listed.rejected).toBe(1); // not SemVer
    expect(pypi.report().listed.rejected).toBe(0); // a valid PEP 440 pre-release
  });
  it("skips GIT ranges, as the load does", () => {
    const census = new Census("npm");
    census.add(rec("GHSA-1", pkg("npm", "x", { ranges: [{ type: "GIT", events: [{ introduced: "abc123" }, { fixed: "def456" }] }] })));
    expect(census.report().boundaries.total).toBe(0);
  });
  it("counts only the packages of its own ecosystem in a record that spans several", () => {
    const record = rec("GHSA-1", pkg("npm", "a"), pkg("npm", "b"), pkg("PyPI", "c"), pkg("RubyGems", "d"));
    const npm = new Census("npm");
    const pypi = new Census("pypi");
    npm.add(record);
    pypi.add(record);
    expect(npm.report().packages).toBe(2);
    expect(pypi.report().packages).toBe(1);
  });
  it("reports names that more than one spelling reaches", () => {
    const census = new Census("pypi");
    census.add(rec("GHSA-1", pkg("PyPI", "Foo_Bar")));
    census.add(rec("GHSA-2", pkg("PyPI", "foo-bar")));
    census.add(rec("GHSA-3", pkg("PyPI", "unrelated")));
    expect(census.report().merged).toEqual({ names: 1, examples: [["Foo_Bar", "foo-bar"]] });
    expect(census.report().packages).toBe(2);
  });
  it("reports a name too long for a KV key", () => {
    const census = new Census("npm");
    census.add(rec("GHSA-1", pkg("npm", "x".repeat(600))));
    census.add(rec("GHSA-2", pkg("npm", "fine")));
    expect(census.report().oversizedKeys).toBe(1);
  });
  it("separates records that are not OSV at all from ones that abort a batch", () => {
    const census = new Census("npm");
    for (const junk of [null, "text", 5, [], {}, { id: "x" }, { modified: "y" }]) census.add(junk);
    census.add({ id: "GHSA-bad", modified: "2026-11-06T00:00:00Z", affected: {} });
    census.add({ id: "GHSA-bad2", modified: "2026-11-06T00:00:00Z", affected: [pkg("npm", "x", { ranges: "nope" })] });
    expect(census.report()).toMatchObject({ records: 2, malformed: 7, unreadable: 2 });
  });
  it("tells malware found by the MAL- id, by a MAL- alias, and by the CWE rule alone", () => {
    const census = new Census("npm");
    for (const name of ["MAL-2024-11183.json", "GHSA-mh6f-8j2x-4483.json", "GHSA-73qr-pfmq-6rp8.json", "GHSA-35jh-r3h4-6jhm.json"]) census.add(fixture(name));
    // solana (MAL-), event-stream and coa (GHSA, CWE-506); lodash is a vulnerability, not malware.
    expect(census.report().malware).toEqual({ records: 3, byPrefix: 1, byAlias: 0, byCwe: 2 });
  });
  it("counts a record whose own id is not MAL- but whose alias is, apart from both", () => {
    const census = new Census("npm");
    census.add({ id: "GHSA-aaaa-bbbb-cccc", modified: "2026-11-06T00:00:00Z", aliases: ["MAL-2026-1"], affected: [pkg("npm", "evil", { versions: ["1.0.0"] })] });
    census.add({ id: "GHSA-dddd-eeee-ffff", modified: "2026-11-06T00:00:00Z", aliases: ["CVE-2026-1"], affected: [pkg("npm", "fine", { versions: ["1.0.0"] })] });
    expect(census.report().malware).toEqual({ records: 1, byPrefix: 0, byAlias: 1, byCwe: 0 });
  });
  it("reads every real fixture without a record it cannot distil", () => {
    const names = readdirSync(FIXTURES).filter((f) => /^(GHSA|MAL)-.*\.json$/.test(f));
    for (const ecosystem of ["npm", "pypi"] as const) {
      const census = new Census(ecosystem);
      for (const name of names) census.add(fixture(name));
      expect(census.report().unreadable, ecosystem).toBe(0);
      expect(census.report().malformed, ecosystem).toBe(0);
    }
  });
});

describe("findings", () => {
  it("is empty for a clean feed, and says so", () => {
    const census = new Census("npm");
    census.add(fixture("MAL-2024-11183.json"));
    expect(findings(census.report())).toEqual([]);
    expect(formatCensus(census.report())).toContain("clean");
  });
  it("names each thing a person must review, with the share of versions affected", () => {
    const census = new Census("npm");
    census.add(rec("GHSA-1", pkg("npm", "x".repeat(600), { versions: ["1.0.0", "bad"], ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0" }] }] })));
    census.add({ id: "GHSA-2", modified: "m", affected: {} });
    census.add(null);
    const text = findings(census.report()).join("\n");
    expect(text).toMatch(/1 of 1 range boundaries \(100\.0%\) cannot be read by the npm comparator, none in malware advisories, so those ranges never match: 1\.0/);
    expect(text).toMatch(/1 of 2 listed versions \(50\.0%\) cannot be read, so they match only the identical string.*bad/);
    expect(text).toMatch(/1 records could not be distilled/);
    expect(text).toMatch(/1 records are not well-formed/);
    expect(text).toMatch(/1 package names are too long/);
    expect(formatCensus(census.report())).toContain("REVIEW:");
  });
  it("lists merged names so someone can check the registry treats them as one", () => {
    const census = new Census("pypi");
    census.add(rec("GHSA-1", pkg("PyPI", "A_B")));
    census.add(rec("GHSA-2", pkg("PyPI", "a-b")));
    expect(findings(census.report()).join("\n")).toMatch(/reached by more than one spelling.*A_B = a-b/);
  });
});

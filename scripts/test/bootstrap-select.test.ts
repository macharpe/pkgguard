import { describe, expect, it } from "vitest";
import { ECOSYSTEM_IDS, ENABLED_ECOSYSTEMS } from "../../packages/core/src/index.js";
import { assertGeneratedFor, defaultOutName, parseSyncStateIds, selectEcosystems } from "../lib/bootstrap-select.js";

describe("selectEcosystems", () => {
  it("is every enabled ecosystem, with its OSV name, when none is named", () => {
    const { ecosystems, explicit } = selectEcosystems(undefined);
    expect(explicit).toBe(false);
    expect(ecosystems.map((e) => e.ours)).toEqual([...ENABLED_ECOSYSTEMS]);
    expect(ecosystems).toEqual([
      { ours: "npm", osv: "npm" },
      { ours: "pypi", osv: "PyPI" },
    ]);
  });
  it.each([["pypi"], ["PyPI"]])("takes one ecosystem by id or by OSV's name: %s", (name) => {
    expect(selectEcosystems(name)).toEqual({ ecosystems: [{ ours: "pypi", osv: "PyPI" }], explicit: true });
  });
  it("can name an ecosystem that is defined but not enabled, so its data can go in first", () => {
    // Selection follows the defined list, not the enabled one: that is what lets data be loaded before enabling.
    for (const id of ECOSYSTEM_IDS) expect(selectEcosystems(id).ecosystems[0]?.ours).toBe(id);
    const notEnabled = ECOSYSTEM_IDS.filter((id) => !ENABLED_ECOSYSTEMS.includes(id));
    expect(notEnabled.length).toBeGreaterThan(0);
    for (const id of notEnabled) {
      expect(selectEcosystems(id).explicit).toBe(true);
      expect(selectEcosystems(undefined).ecosystems.map((e) => e.ours)).not.toContain(id);
    }
  });
  it("takes Cargo by its id or by OSV's name for it, though it is not enabled", () => {
    expect(selectEcosystems("cargo")).toEqual({ ecosystems: [{ ours: "cargo", osv: "crates.io" }], explicit: true });
    expect(selectEcosystems("crates.io")).toEqual({ ecosystems: [{ ours: "cargo", osv: "crates.io" }], explicit: true });
    expect(defaultOutName(true, selectEcosystems("cargo").ecosystems)).toBe("out-cargo");
  });
  it.each([[""], ["NPM"], ["Pypi"], ["constructor"], ["__proto__"], ["crates"], ["Cargo"], [" npm"], ["npm,pypi"], ["all"]])("refuses %j, listing what is valid", (bad) => {
    expect(() => selectEcosystems(bad)).toThrow(/--ecosystem must name one of: npm \(OSV: npm\), pypi \(OSV: PyPI\), cargo \(OSV: crates\.io\)/);
  });
  it("never reads a flag with no value as 'all'", () => {
    expect(() => selectEcosystems("")).toThrow();
  });
});

describe("defaultOutName", () => {
  it("keeps the full index where it was, and gives each single ecosystem its own directory", () => {
    expect(defaultOutName(false, selectEcosystems(undefined).ecosystems)).toBe("out");
    expect(defaultOutName(true, selectEcosystems("pypi").ecosystems)).toBe("out-pypi");
    expect(defaultOutName(true, selectEcosystems("npm").ecosystems)).toBe("out-npm");
  });
});

describe("parseSyncStateIds", () => {
  it("reads the ecosystems from wrangler's JSON", () => {
    expect(parseSyncStateIds(JSON.stringify([{ results: [{ ecosystem: "npm" }, { ecosystem: "pypi" }], success: true }]))).toEqual(["npm", "pypi"]);
    expect(parseSyncStateIds(JSON.stringify([{ results: [], success: true }]))).toEqual([]);
  });
  it("throws rather than guess when the output is not what it expects", () => {
    for (const bad of ["not json", "{}", "null", JSON.stringify([{ nope: 1 }]), JSON.stringify([{ results: "x" }])]) {
      expect(() => parseSyncStateIds(bad), bad).toThrow();
    }
  });
});

describe("assertGeneratedFor", () => {
  const all = selectEcosystems(undefined).ecosystems;
  const pypi = selectEcosystems("pypi").ecosystems;
  it("accepts a directory generated for exactly what is being loaded", () => {
    expect(() => assertGeneratedFor(["npm", "pypi"], all)).not.toThrow();
    expect(() => assertGeneratedFor(["pypi", "npm"], all)).not.toThrow();
    expect(() => assertGeneratedFor(["pypi"], pypi)).not.toThrow();
  });
  it("takes output from before the stats recorded this to be the full, enabled set", () => {
    expect(() => assertGeneratedFor(undefined, all)).not.toThrow();
    expect(() => assertGeneratedFor(undefined, pypi)).toThrow(/generated for \[npm, pypi\], but this load is for \[pypi\]/);
  });
  it("refuses a single-ecosystem directory for a full load, and the reverse", () => {
    expect(() => assertGeneratedFor(["pypi"], all)).toThrow(/generate again with the same --ecosystem/);
    expect(() => assertGeneratedFor(["npm", "pypi"], pypi)).toThrow(/generate again/);
    expect(() => assertGeneratedFor(["npm"], pypi)).toThrow(/generated for \[npm\], but this load is for \[pypi\]/);
  });
});

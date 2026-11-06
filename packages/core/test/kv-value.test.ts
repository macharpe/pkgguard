import { describe, expect, it } from "vitest";
import { isNegative, parseKvValue } from "../src/osv/kv-value.js";
import { overrideApplies, overrideKey, parseOverride } from "../src/override.js";

const advisory = { id: "GHSA-x", r: [], v: ["1.0.0"] };

describe("parseKvValue", () => {
  it("accepts an index entry", () => {
    const v = parseKvValue({ v: 1, m: [advisory], c: [], u: "t" });
    expect(v && !isNegative(v)).toBe(true);
  });
  it("accepts a negative marker", () => {
    const v = parseKvValue({ v: 1, n: true, u: "t" });
    expect(v && isNegative(v)).toBe(true);
  });
  it.each([
    ["null", null],
    ["a string", "x"],
    ["an array", []],
    ["a future schema version", { v: 2, m: [], c: [], u: "t" }],
    ["no timestamp", { v: 1, m: [], c: [] }],
    ["m not a list", { v: 1, m: {}, c: [], u: "t" }],
    ["c missing", { v: 1, m: [], u: "t" }],
    ["an advisory without ranges", { v: 1, m: [{ id: "x" }], c: [], u: "t" }],
    ["an advisory with a numeric id", { v: 1, m: [{ id: 1, r: [], v: [] }], c: [], u: "t" }],
    ["n set to a non-true value", { v: 1, n: false, u: "t" }],
  ])("rejects %s", (_name, raw) => {
    expect(parseKvValue(raw)).toBeNull();
  });
});

describe("overrides", () => {
  it("builds a normalized key per mode", () => {
    expect(overrideKey("block", "npm", "@Babel/Core")).toBe("override:block:npm:@babel/core");
    expect(overrideKey("allow", "pypi", "Typing_Extensions")).toBe("override:allow:pypi:typing-extensions");
  });
  it("refuses a key over the KV limit", () => {
    expect(overrideKey("block", "npm", "a".repeat(600))).toBeNull();
  });
  it("parses the two valid shapes and rejects the rest", () => {
    expect(parseOverride({ v: 1, versions: null })).not.toBeNull();
    expect(parseOverride({ v: 1, versions: ["1.0.0"], note: "n" })).not.toBeNull();
    for (const bad of [null, [], "x", { v: 2, versions: null }, { v: 1 }, { v: 1, versions: [1] }, { v: 1, versions: "1.0.0" }]) {
      expect(parseOverride(bad), JSON.stringify(bad)).toBeNull();
    }
  });
  it("a null version list covers every version, including unparseable ones", () => {
    expect(overrideApplies("npm", { v: 1, versions: null }, "1.2.3")).toBe(true);
    expect(overrideApplies("npm", { v: 1, versions: null }, "not-a-version")).toBe(true);
  });
  it("a version list matches exactly, by value not by string", () => {
    const o = { v: 1 as const, versions: ["1.0.0"] };
    expect(overrideApplies("npm", o, "1.0.0")).toBe(true);
    expect(overrideApplies("npm", o, "1.0.1")).toBe(false);
    expect(overrideApplies("pypi", { v: 1, versions: ["1.0"] }, "1.0.0")).toBe(true);
  });
});

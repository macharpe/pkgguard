import { describe, expect, it } from "vitest";
import { compareVersions, comparePep440, compareSemver, parsePep440 } from "../src/version/index.js";

describe("PEP 440", () => {
  it("orders the canonical sequence from the PEP, strictly ascending", () => {
    const ascending = [
      "1.0.dev456",
      "1.0a1",
      "1.0a2.dev456",
      "1.0a12.dev456",
      "1.0a12",
      "1.0b1.dev456",
      "1.0b2",
      "1.0b2.post345.dev456",
      "1.0b2.post345",
      "1.0rc1.dev456",
      "1.0rc1",
      "1.0",
      "1.0+abc.5",
      "1.0+abc.7",
      "1.0+5",
      "1.0.post456.dev34",
      "1.0.post456",
      "1.1.dev1",
    ];
    for (let i = 0; i < ascending.length; i++) {
      for (let j = 0; j < ascending.length; j++) {
        const expected = i === j ? 0 : i < j ? -1 : 1;
        expect(comparePep440(ascending[i]!, ascending[j]!), `${ascending[i]} vs ${ascending[j]}`).toBe(expected);
      }
    }
  });

  it("epochs dominate the release segment", () => {
    expect(comparePep440("1!1.0", "2.0")).toBe(1);
    expect(comparePep440("1!2.0", "2!1.0")).toBe(-1);
    expect(comparePep440("0!1.0", "1.0")).toBe(0);
  });

  it.each([
    ["1.0", "1.0.0"],
    ["1.0", "1.0.0.0"],
    ["1.0-1", "1.0.post1"],
    ["1.0RC1", "1.0rc1"],
    ["1.0alpha1", "1.0a1"],
    ["1.0beta2", "1.0b2"],
    ["1.0c1", "1.0rc1"],
    ["1.0.pre1", "1.0rc1"],
    ["1.0.rev3", "1.0.post3"],
    ["1.0.r3", "1.0.post3"],
    ["v1.0", "1.0"],
    ["1.0a", "1.0a0"],
    ["1.0.post", "1.0.post0"],
    ["1.0.dev", "1.0.dev0"],
    ["1.0+Ubuntu.1", "1.0+ubuntu-1"],
  ])("normalizes: %s == %s", (a, b) => {
    expect(comparePep440(a, b)).toBe(0);
  });

  it("local versions of different shapes: ints beat strings, longer beats prefix", () => {
    expect(comparePep440("1.0+5", "1.0+abc")).toBe(1);
    expect(comparePep440("1.0+abc.1", "1.0+abc")).toBe(1);
    expect(comparePep440("1.0+abc", "1.0")).toBe(1);
  });

  it("compares numerically, not lexically", () => {
    expect(comparePep440("1.10", "1.9")).toBe(1);
    expect(comparePep440("1.0rc10", "1.0rc9")).toBe(1);
  });

  it.each(["", "abc", "1.0.", "1..0", "1.0+", "1.0-", "1.0 beta", "1.0.0.x", "!1.0", "1!"])(
    "rejects invalid version %j",
    (v) => {
      expect(parsePep440(v)).toBeNull();
      expect(comparePep440(v, "1.0")).toBeNull();
      expect(comparePep440("1.0", v)).toBeNull();
    },
  );

  it("rejects integers beyond the safe range instead of comparing garbage", () => {
    expect(parsePep440("1.99999999999999999999")).toBeNull();
  });

  it("accepts surrounding whitespace", () => {
    expect(comparePep440("  1.0  ", "1.0")).toBe(0);
  });
});

describe("SemVer (npm)", () => {
  it("orders prereleases before the release", () => {
    expect(compareSemver("1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(compareSemver("1.0.0-alpha", "1.0.0-beta")).toBe(-1);
    expect(compareSemver("1.0.0-rc.2", "1.0.0-rc.10")).toBe(-1);
  });
  it("compares numerically", () => {
    expect(compareSemver("1.10.0", "1.9.0")).toBe(1);
    expect(compareSemver("4.17.21", "4.17.21")).toBe(0);
    expect(compareSemver("4.17.20", "4.17.21")).toBe(-1);
  });
  it("ignores build metadata", () => {
    expect(compareSemver("1.0.0+a", "1.0.0+b")).toBe(0);
  });
  it.each(["", "1.0", "latest", "v", "1.0.0.0", "^1.2.3"])("rejects %j", (v) => {
    expect(compareSemver(v, "1.0.0")).toBeNull();
  });
});

describe("compareVersions dispatch", () => {
  it("uses PEP 440 for pypi and SemVer for npm", () => {
    expect(compareVersions("pypi", "1.0.post1", "1.0")).toBe(1);
    expect(compareVersions("npm", "1.0.0-rc.1", "1.0.0")).toBe(-1);
  });
  it("a PEP 440 version is not a valid npm version and vice versa", () => {
    expect(compareVersions("npm", "1.0", "1.0.0")).toBeNull();
    expect(compareVersions("pypi", "1.0.0-beta.foo", "1.0.0")).toBeNull();
    expect(compareVersions("npm", "1!2.0", "1.0.0")).toBeNull();
  });
});

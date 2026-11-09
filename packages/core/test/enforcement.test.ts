import { describe, expect, it } from "vitest";
import { ECOSYSTEM_IDS } from "../src/ecosystem-ids.js";
import { ENFORCEMENT_KEY, enforcementReport, parseEnforcement, parseEnforcementText, sameEnforcement } from "../src/enforcement.js";
import { kvKey } from "../src/normalize.js";

const AT = "2026-11-09T10:00:00.000Z";

describe("ENFORCEMENT_KEY", () => {
  it("cannot collide with an index key: no ecosystem is called meta", () => {
    expect(ENFORCEMENT_KEY.startsWith("meta:")).toBe(true);
    expect((ECOSYSTEM_IDS as readonly string[]).includes("meta")).toBe(false);
    for (const id of ECOSYSTEM_IDS) expect(kvKey(id, "enforcement")).not.toBe(ENFORCEMENT_KEY);
  });
});

describe("enforcementReport", () => {
  it("copies enforce and stamps the time", () => {
    expect(enforcementReport({ enforce: true, observeOnly: new Set() }, AT)).toEqual({ enforce: true, observeOnly: [], reportedAt: AT });
    expect(enforcementReport({ enforce: false, observeOnly: new Set() }, AT).enforce).toBe(false);
  });
  it("lists observe-only ecosystems in registry order, whatever order the set was built in", () => {
    const a = enforcementReport({ enforce: true, observeOnly: new Set(["go", "pypi", "cargo"] as const) }, AT);
    const b = enforcementReport({ enforce: true, observeOnly: new Set(["cargo", "go", "pypi"] as const) }, AT);
    expect(a.observeOnly).toEqual(["pypi", "cargo", "go"]);
    expect(b.observeOnly).toEqual(a.observeOnly);
  });
  it("reports every ecosystem when all are observe-only", () => {
    expect(enforcementReport({ enforce: true, observeOnly: new Set(ECOSYSTEM_IDS) }, AT).observeOnly).toEqual([...ECOSYSTEM_IDS]);
  });
});

describe("sameEnforcement", () => {
  const base = { enforce: true, observeOnly: ["pypi"] as const };
  it("is true for the same behaviour", () => {
    expect(sameEnforcement({ enforce: true, observeOnly: ["pypi"] }, base as never)).toBe(true);
    expect(sameEnforcement({ enforce: false, observeOnly: [] }, { enforce: false, observeOnly: [] })).toBe(true);
  });
  it("is false when enforce differs", () => {
    expect(sameEnforcement({ enforce: false, observeOnly: ["pypi"] }, base as never)).toBe(false);
  });
  it("is false when the observe-only lists differ in length, member or order", () => {
    expect(sameEnforcement({ enforce: true, observeOnly: [] }, base as never)).toBe(false);
    expect(sameEnforcement({ enforce: true, observeOnly: ["pypi", "go"] }, base as never)).toBe(false);
    expect(sameEnforcement({ enforce: true, observeOnly: ["go"] }, base as never)).toBe(false);
    expect(sameEnforcement({ enforce: true, observeOnly: ["go", "pypi"] }, { enforce: true, observeOnly: ["pypi", "go"] })).toBe(false);
  });
});

describe("parseEnforcement", () => {
  it("accepts a well-formed report", () => {
    expect(parseEnforcement({ enforce: true, observeOnly: ["pypi", "go"], reportedAt: AT })).toEqual({ enforce: true, observeOnly: ["pypi", "go"], reportedAt: AT });
    expect(parseEnforcement({ enforce: false, observeOnly: [], reportedAt: AT })).toEqual({ enforce: false, observeOnly: [], reportedAt: AT });
  });
  it("drops ids it does not know and keeps the rest, in registry order", () => {
    expect(parseEnforcement({ enforce: true, observeOnly: ["go", "maven", 7, null, "npm", "npm"], reportedAt: AT })?.observeOnly).toEqual(["npm", "go"]);
  });
  it.each([
    ["null", null],
    ["a string", "enforcing"],
    ["an array", []],
    ["a number", 1],
    ["missing enforce", { observeOnly: [], reportedAt: AT }],
    ["enforce as a string", { enforce: "true", observeOnly: [], reportedAt: AT }],
    ["enforce as 1", { enforce: 1, observeOnly: [], reportedAt: AT }],
    ["observeOnly missing", { enforce: true, reportedAt: AT }],
    ["observeOnly as a string", { enforce: true, observeOnly: "pypi", reportedAt: AT }],
    ["reportedAt missing", { enforce: true, observeOnly: [] }],
    ["reportedAt not a string", { enforce: true, observeOnly: [], reportedAt: 5 }],
    ["reportedAt not a date", { enforce: true, observeOnly: [], reportedAt: "yesterday-ish" }],
  ])("returns null for %s, never a default that could read as 'off'", (_name, value) => {
    expect(parseEnforcement(value)).toBeNull();
  });
});

describe("parseEnforcementText", () => {
  it("parses stored JSON", () => {
    expect(parseEnforcementText(JSON.stringify({ enforce: true, observeOnly: [], reportedAt: AT }))?.enforce).toBe(true);
  });
  it.each([null, "", "{not json", "[]", "null", '"x"'])("returns null for %j", (text) => {
    expect(parseEnforcementText(text)).toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import { inRange, isVersionAffected } from "../src/osv/match.js";

describe("inRange — semver", () => {
  const range = [{ introduced: "0" }, { fixed: "4.17.21" }];
  it("introduced 0 to fixed", () => {
    expect(inRange("npm", range, "0.0.1")).toBe(true);
    expect(inRange("npm", range, "4.17.20")).toBe(true);
    expect(inRange("npm", range, "4.17.21")).toBe(false);
    expect(inRange("npm", range, "5.0.0")).toBe(false);
  });
  it("introduced is inclusive, fixed is exclusive", () => {
    const r = [{ introduced: "3.3.6" }, { fixed: "4.0.0" }];
    expect(inRange("npm", r, "3.3.5")).toBe(false);
    expect(inRange("npm", r, "3.3.6")).toBe(true);
    expect(inRange("npm", r, "3.9.9")).toBe(true);
    expect(inRange("npm", r, "4.0.0")).toBe(false);
  });
  it("last_affected is inclusive", () => {
    const r = [{ introduced: "0" }, { last_affected: "4.5.0" }];
    expect(inRange("npm", r, "4.5.0")).toBe(true);
    expect(inRange("npm", r, "4.5.1")).toBe(false);
  });
  it("open-ended range affects everything from introduced", () => {
    const r = [{ introduced: "1.0.0" }];
    expect(inRange("npm", r, "0.9.0")).toBe(false);
    expect(inRange("npm", r, "99.0.0")).toBe(true);
  });
  it("multiple introduced/fixed windows", () => {
    const r = [{ introduced: "1.0.0" }, { fixed: "1.5.0" }, { introduced: "2.0.0" }, { fixed: "2.3.0" }];
    expect(inRange("npm", r, "1.2.0")).toBe(true);
    expect(inRange("npm", r, "1.7.0")).toBe(false);
    expect(inRange("npm", r, "2.1.0")).toBe(true);
    expect(inRange("npm", r, "2.3.0")).toBe(false);
  });
  it("does not depend on event order in the record", () => {
    const r = [{ fixed: "2.3.0" }, { introduced: "2.0.0" }, { fixed: "1.5.0" }, { introduced: "1.0.0" }];
    expect(inRange("npm", r, "1.2.0")).toBe(true);
    expect(inRange("npm", r, "1.7.0")).toBe(false);
    expect(inRange("npm", r, "2.1.0")).toBe(true);
  });
  it("a prerelease of the fixed version is still affected", () => {
    expect(inRange("npm", [{ introduced: "0" }, { fixed: "2.0.0" }], "2.0.0-rc.1")).toBe(true);
  });
});

describe("inRange — PEP 440", () => {
  it("uses PEP 440 ordering, not semver", () => {
    const r = [{ introduced: "0" }, { fixed: "2.0" }];
    expect(inRange("pypi", r, "2.0.dev1")).toBe(true);
    expect(inRange("pypi", r, "2.0rc1")).toBe(true);
    expect(inRange("pypi", r, "2.0")).toBe(false);
    expect(inRange("pypi", r, "2.0.post1")).toBe(false);
  });
  it("epoch handling", () => {
    const r = [{ introduced: "0" }, { fixed: "2.0" }];
    expect(inRange("pypi", r, "1!1.0")).toBe(false);
    expect(inRange("pypi", [{ introduced: "1!0" }, { fixed: "1!2.0" }], "1!1.5")).toBe(true);
  });
});

describe("inRange — failure modes return false, never throw", () => {
  it("unparseable target version", () => {
    expect(inRange("npm", [{ introduced: "0" }], "not-a-version")).toBe(false);
    expect(inRange("pypi", [{ introduced: "0" }], "???")).toBe(false);
  });
  it("unparseable event version", () => {
    expect(inRange("npm", [{ introduced: "0" }, { fixed: "garbage" }], "1.0.0")).toBe(false);
  });
  it("empty events and unknown event keys", () => {
    expect(inRange("npm", [], "1.0.0")).toBe(false);
    expect(inRange("npm", [{ limit: "2.0.0" }], "1.0.0")).toBe(false);
  });
});

describe("isVersionAffected", () => {
  it("all matches everything, even unparseable versions", () => {
    expect(isVersionAffected("npm", { r: [], v: [], all: true }, "whatever")).toBe(true);
  });
  it("explicit versions", () => {
    const spec = { r: [], v: ["9.1.6", "9.2.3"] };
    expect(isVersionAffected("npm", spec, "9.1.6")).toBe(true);
    expect(isVersionAffected("npm", spec, "9.1.7")).toBe(false);
  });
  it("explicit versions match across PEP 440 spellings", () => {
    expect(isVersionAffected("pypi", { r: [], v: ["1.0"] }, "1.0.0")).toBe(true);
  });
  it("explicit string match works even when the version is unparseable", () => {
    expect(isVersionAffected("npm", { r: [], v: ["weird"] }, "weird")).toBe(true);
  });
  it("an empty spec affects nothing", () => {
    expect(isVersionAffected("npm", { r: [], v: [] }, "1.0.0")).toBe(false);
  });
  it("ranges and versions combine", () => {
    const spec = { r: [[{ introduced: "1.0.0" }, { fixed: "1.1.0" }]], v: ["3.0.0"] };
    expect(isVersionAffected("npm", spec, "1.0.5")).toBe(true);
    expect(isVersionAffected("npm", spec, "3.0.0")).toBe(true);
    expect(isVersionAffected("npm", spec, "2.0.0")).toBe(false);
  });
});

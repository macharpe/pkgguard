import { describe, expect, it } from "vitest";
import { kvKey, normalizeName, normalizePypiName } from "../src/normalize.js";

describe("normalize", () => {
  it("npm lowercases so a case variant cannot bypass lookup", () => {
    expect(normalizeName("npm", "JSONStream")).toBe("jsonstream");
    expect(normalizeName("npm", "@Babel/Core")).toBe("@babel/core");
  });
  it.each([
    ["Typing_Extensions", "typing-extensions"],
    ["zope.interface", "zope-interface"],
    ["a--b__c..d-_.e", "a-b-c-d-e"],
    ["  Requests ", "requests"],
  ])("PEP 503: %s -> %s", (input, expected) => {
    expect(normalizePypiName(input)).toBe(expected);
  });
  it("kvKey is ecosystem-prefixed", () => {
    expect(kvKey("npm", "lodash")).toBe("npm:lodash");
    expect(kvKey("npm", "@babel/core")).toBe("npm:@babel/core");
    expect(kvKey("pypi", "Foo_Bar")).toBe("pypi:foo-bar");
  });
  it("kvKey is null past the 512-byte limit, never throws", () => {
    expect(kvKey("npm", "a".repeat(600))).toBeNull();
    expect(kvKey("npm", "a".repeat(500))).not.toBeNull();
  });
});

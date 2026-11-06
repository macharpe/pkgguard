import { describe, expect, it } from "vitest";
import { parseEnvFile } from "../lib/deploy-env.js";

describe("parseEnvFile", () => {
  it("parses KEY=value, export, quotes and comments", () => {
    expect(
      parseEnvFile(`# comment\n\nPKGGUARD_A=1\nexport PKGGUARD_B="two words"\nPKGGUARD_C='x'\n`),
    ).toEqual({ PKGGUARD_A: "1", PKGGUARD_B: "two words", PKGGUARD_C: "x" });
  });
  it("keeps '=' inside values", () => {
    expect(parseEnvFile("PKGGUARD_A=a=b=c")).toEqual({ PKGGUARD_A: "a=b=c" });
  });
  it("treats a malformed line as an error, never silently skips it", () => {
    expect(() => parseEnvFile("PKGGUARD_A=1\nthis is not valid")).toThrow(/line 2/);
    expect(() => parseEnvFile("lowercase=1")).toThrow(/malformed/);
  });
});

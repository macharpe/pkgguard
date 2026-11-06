import { webcrypto } from "node:crypto";
import { describe, expect, it } from "vitest";
import { REFERENCE_PATTERN, isReference, newReference } from "../src/reference.js";

const real = (bytes: Uint8Array<ArrayBuffer>) => webcrypto.getRandomValues(bytes);
const fixed = (values: number[]) => (bytes: Uint8Array) => (bytes.set(values), bytes);

describe("newReference", () => {
  it("has the shape PG- plus six characters from the unambiguous alphabet", () => {
    for (let i = 0; i < 500; i++) expect(newReference(real)).toMatch(REFERENCE_PATTERN);
  });
  it("never uses the letters that are mistaken for digits, or U", () => {
    const seen = new Set(Array.from({ length: 2000 }, () => newReference(real).slice(3)).join(""));
    for (const bad of "ILOU") expect(seen.has(bad), bad).toBe(false);
  });
  it("maps each byte through the alphabet by its low five bits", () => {
    expect(newReference(fixed([0, 1, 2, 3, 4, 5]))).toBe("PG-012345");
    expect(newReference(fixed([31, 30, 29, 28, 27, 26]))).toBe("PG-ZYXWVT");
  });
  it("has no modulo bias: bytes that differ only above the low five bits give the same character", () => {
    expect(newReference(fixed([0, 0, 0, 0, 0, 0]))).toBe(newReference(fixed([32, 64, 96, 128, 160, 224])));
  });
  it("uses all six bytes, in order", () => {
    expect(newReference(fixed([1, 0, 0, 0, 0, 0]))).toBe("PG-100000");
    expect(newReference(fixed([0, 0, 0, 0, 0, 1]))).toBe("PG-000001");
  });
  it("is different each time with the real generator", () => {
    expect(new Set(Array.from({ length: 300 }, () => newReference(real))).size).toBe(300);
  });
});

describe("isReference", () => {
  it("accepts a generated reference", () => {
    expect(isReference(newReference(real))).toBe(true);
    expect(isReference("PG-7Q2K4M")).toBe(true);
  });
  it.each(["", "PG-", "PG-7Q2K4", "PG-7Q2K4MM", "pg-7q2k4m", "PG-7Q2K4I", "PG-7Q2K4O", "PG-7Q2K4U", "XX-7Q2K4M", " PG-7Q2K4M", "PG-7Q2K4M\n", "PG-7Q2K4M extra", null, undefined, 5])("rejects %j", (v) => {
    expect(isReference(v)).toBe(false);
  });
});

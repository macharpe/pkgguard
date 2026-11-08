import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildKvEntry,
  classify,
  compareVersions,
  distillFor,
  evaluate,
  isVersionAffected,
  kvKey,
  normalizeName,
  parseCargoUrl,
  summarizeVerdict,
  toPurl,
  type OsvRecord,
} from "../src/index.js";

const FIXTURES = join(import.meta.dirname, "fixtures");
const record = (name: string): OsvRecord => JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as OsvRecord;

const parse = (url: string) => parseCargoUrl(new URL(url));
const crate = (name: string, version: string) => [{ ecosystem: "cargo", namespace: null, name, version }];

describe("parseCargoUrl: the two shapes the registry serves", () => {
  it("reads what the cargo client requests, measured behind Gateway", () => {
    expect(parse("https://static.crates.io/crates/itoa/1.0.11/download")).toEqual(crate("itoa", "1.0.11"));
  });
  it("reads the shape that redirects to, and that Cloudflare documents", () => {
    expect(parse("https://static.crates.io/crates/itoa/itoa-1.0.11.crate")).toEqual(crate("itoa", "1.0.11"));
  });
  it("reads the API's download URL, which redirects to the other two", () => {
    expect(parse("https://crates.io/api/v1/crates/serde/1.0.200/download")).toEqual(crate("serde", "1.0.200"));
  });
  it("keeps the name as it is spelled, underscores included", () => {
    expect(parse("https://static.crates.io/crates/serde_json/1.0.100/download")).toEqual(crate("serde_json", "1.0.100"));
    expect(parse("https://static.crates.io/crates/serde_json/serde_json-1.0.100.crate")).toEqual(crate("serde_json", "1.0.100"));
  });
  it("takes the name from the path, so a hyphenated name or version cannot confuse the split", () => {
    expect(parse("https://static.crates.io/crates/tokio-util/tokio-util-0.7.10.crate")).toEqual(crate("tokio-util", "0.7.10"));
    expect(parse("https://static.crates.io/crates/serde/serde-1.0.0-rc.1.crate")).toEqual(crate("serde", "1.0.0-rc.1"));
    expect(parse("https://static.crates.io/crates/a-b/a-b-1.0.0-beta-2.crate")).toEqual(crate("a-b", "1.0.0-beta-2"));
  });
  it("keeps prerelease and build metadata in the version", () => {
    expect(parse("https://static.crates.io/crates/foo/1.0.0-rc.1/download")).toEqual(crate("foo", "1.0.0-rc.1"));
    expect(parse("https://static.crates.io/crates/foo/1.0.0+build.5/download")).toEqual(crate("foo", "1.0.0+build.5"));
    expect(parse("https://static.crates.io/crates/foo/1.0.0-rc.1+b.2/download")).toEqual(crate("foo", "1.0.0-rc.1+b.2"));
  });
  it("tolerates a mirror's path prefix, as the npm parser does", () => {
    expect(parse("https://mirror.example.com/artifactory/api/cargo/cargo-remote/api/v1/crates/serde/1.0.200/download")).toEqual(crate("serde", "1.0.200"));
    expect(parse("https://mirror.example.com/repository/crates/crates/serde/serde-1.0.200.crate")).toEqual(crate("serde", "1.0.200"));
  });
  it("ignores the query string and fragment", () => {
    expect(parse("https://static.crates.io/crates/itoa/1.0.11/download?x=1#frag")).toEqual(crate("itoa", "1.0.11"));
  });
  it("decodes percent-encoded segments", () => {
    expect(parse("https://static.crates.io/crates/serde%5Fjson/1.0.100/download")).toEqual(crate("serde_json", "1.0.100"));
  });
});

describe("parseCargoUrl: what is not a download", () => {
  it.each([
    "https://index.crates.io/config.json",
    "https://index.crates.io/it/oa/itoa",
    "https://static.crates.io/crates/itoa",
    "https://static.crates.io/crates/itoa/1.0.11",
    "https://static.crates.io/crates/itoa/download",
    "https://static.crates.io/download",
    "https://crates.io/crates/itoa",
    "https://static.crates.io/crates/itoa/itoa-1.0.11.tar.gz",
    "https://static.crates.io/crates/itoa/other-1.0.11.crate",
    // Same length as "itoa-", so only the prefix check itself can reject it.
    "https://static.crates.io/crates/itoa/abcd-1.0.11.crate",
    "https://static.crates.io/crates/itoa/Itoa-1.0.11.crate",
    // The .crate shape needs its `crates` segment just as the /download shape does.
    "https://static.crates.io/itoa/itoa-1.0.11.crate",
    "https://static.crates.io/other/itoa/itoa-1.0.11.crate",
    "https://static.crates.io/crates/itoa/itoa-.crate",
    "https://static.crates.io/itoa/1.0.11/download",
    "https://static.crates.io/crates//1.0.11/download",
    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
    "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0.tar.gz",
  ])("%s", (url) => expect(parse(url)).toEqual([]));

  it.each([
    ["a version that is not strict SemVer", "https://static.crates.io/crates/itoa/1.0/download"],
    ["the word latest", "https://static.crates.io/crates/itoa/latest/download"],
    ["a leading v", "https://static.crates.io/crates/itoa/v1.0.11/download"],
    ["a four-part version", "https://static.crates.io/crates/itoa/1.0.11.1/download"],
    ["a name with a dot", "https://static.crates.io/crates/a.b/1.0.0/download"],
    ["a name with a space", "https://static.crates.io/crates/a%20b/1.0.0/download"],
    ["a name that is a traversal", "https://static.crates.io/crates/../1.0.0/download"],
    ["an encoded slash in the name", "https://static.crates.io/crates/ef%2Fevil/1.0.0/download"],
    ["a name over 64 characters", `https://static.crates.io/crates/${"a".repeat(65)}/1.0.0/download`],
    ["a malformed escape", "https://static.crates.io/crates/%E0%A4%A/1.0.0/download"],
  ])("refuses %s", (_label, url) => expect(parse(url)).toEqual([]));

  it("accepts a name of exactly 64 characters", () => {
    expect(parse(`https://static.crates.io/crates/${"a".repeat(64)}/1.0.0/download`)).toHaveLength(1);
  });
});

describe("Cargo names", () => {
  it("fold case and the underscore, as crates.io does, on both sides", () => {
    for (const spelling of ["Serde_Json", "serde_json", "serde-json", "SERDE-JSON", " serde_json "]) {
      expect(normalizeName("cargo", spelling), spelling).toBe("serde-json");
      expect(kvKey("cargo", spelling), spelling).toBe("cargo:serde-json");
    }
  });
  it("keeps the crate's own spelling in the package URL", () => {
    expect(toPurl({ ecosystem: "cargo", namespace: null, name: "serde_json", version: "1.0.100" })).toBe("pkg:cargo/serde_json@1.0.100");
  });
});

describe("Cargo versions", () => {
  it("order as SemVer, prerelease below release", () => {
    expect(compareVersions("cargo", "1.0.0-alpha", "1.0.0")).toBe(-1);
    expect(compareVersions("cargo", "1.10.0", "1.9.0")).toBe(1);
    expect(compareVersions("cargo", "0.0.0-0", "0.0.0")).toBe(-1);
    expect(compareVersions("cargo", "1.0.0+a", "1.0.0+b")).toBe(0);
  });
  it("are unreadable when they are not SemVer, which the census reports", () => {
    expect(compareVersions("cargo", "0.65", "0.65")).toBeNull();
  });
});

describe("real Cargo advisories", () => {
  // `finch_cli_rust` was removed from crates.io for malicious code. Its id is GHSA-…, not MAL-…, so a check on the
  // prefix would miss it: the Cargo counterpart of event-stream.
  const finch = record("cargo-GHSA-6v2j-vr4h-f632.json");
  // The `time` crate's segfault: a vulnerability with many ranges whose boundaries are prereleases such as 0.2.1-0.
  const time = record("cargo-RUSTSEC-2020-0071.json");

  it("finds malware by the CWE rule where the MAL- prefix finds none", () => {
    expect(finch.id.startsWith("MAL-")).toBe(false);
    expect(classify(finch)).toBe("malware");
  });
  it("folds the crate's name when it distils it", () => {
    const [row] = distillFor(finch, ["cargo"]);
    expect(row).toMatchObject({ ecosystem: "cargo", packageName: "finch-cli-rust", kind: "malware", namespace: null });
  });
  it("blocks every version of that malware, through the same path the filter takes", () => {
    const entry = buildKvEntry(distillFor(finch, ["cargo"]), "2026-11-08T00:00:00Z");
    for (const version of ["0.0.1", "0.1.0", "9.9.9"]) {
      expect(summarizeVerdict(evaluate("cargo", entry!, version)).outcome, version).toBe("blocked");
    }
  });
  it("classifies the `time` advisory as a vulnerability, never as malware", () => {
    expect(classify(time)).toBe("vulnerability");
    expect(distillFor(time, ["cargo"])[0]?.kind).toBe("vulnerability");
  });
  it("matches the affected ranges of `time` and not the fixed versions, across prerelease boundaries", () => {
    const [row] = distillFor(time, ["cargo"]);
    const affected = (version: string) => isVersionAffected("cargo", row!.spec, version);
    expect(["0.0.1", "0.1.43", "0.2.22"].map(affected)).toEqual([true, true, true]);
    expect(["0.2.0", "0.2.1", "0.2.23", "0.2.24", "0.3.0", "1.0.0"].map(affected)).toEqual([false, false, false, false, false, false]);
  });
  it("flags the `time` vulnerability and does not block it", () => {
    const entry = buildKvEntry(distillFor(time, ["cargo"]), "2026-11-08T00:00:00Z");
    expect(summarizeVerdict(evaluate("cargo", entry!, "0.1.43")).outcome).toBe("flagged");
    expect(summarizeVerdict(evaluate("cargo", entry!, "0.3.0")).outcome).toBe("allowed");
  });
  it("is read by the distiller the refresh uses, now that Cargo is enabled", async () => {
    const { distill } = await import("../src/index.js");
    expect(distill(finch).map((r) => r.ecosystem)).toEqual(["cargo"]);
    expect(distill(time).map((r) => r.ecosystem)).toEqual(["cargo"]);
  });
});

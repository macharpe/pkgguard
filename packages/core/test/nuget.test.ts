import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildKvEntry,
  classify,
  compareNuget,
  compareVersions,
  distillFor,
  evaluate,
  isVersionAffected,
  kvKey,
  normalizeName,
  parseNugetUrl,
  parseNugetVersion,
  summarizeVerdict,
  toPurl,
  type KvEntry,
  type OsvRecord,
} from "../src/index.js";

const FIXTURES = join(import.meta.dirname, "fixtures");
const record = (name: string): OsvRecord => JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as OsvRecord;
const parse = (url: string) => parseNugetUrl(new URL(url));
const pkg = (name: string, version: string) => ({ ecosystem: "nuget", namespace: null, name, version });
const flat = (id: string, version: string, file = `${id}.${version}.nupkg`) => `https://api.nuget.org/v3-flatcontainer/${id}/${version}/${file}`;

describe("compareNuget against NuGet's own NuGet.Versioning", () => {
  // Produced by scripts/oracles/nuget-version/, which asks NuGet about the real feed's version strings and package names.
  // .NET is not needed to run this: the answers are committed.
  const oracle = JSON.parse(readFileSync(join(FIXTURES, "nuget-version-oracle.json"), "utf8")) as {
    generatedWith: string;
    feedVersions: number;
    feedRefusedByNuGet: string[];
    adjacent: string[];
    random: string[];
    handpicked: string[];
    refused: string[];
    nameFold: Array<[string, string]>;
  };
  const split = (pair: string): [string, string, -1 | 0 | 1] => {
    const last = pair.lastIndexOf("|");
    const rest = pair.slice(0, last);
    const mid = rest.indexOf("|");
    return [rest.slice(0, mid), rest.slice(mid + 1), Number(pair.slice(last + 1)) as -1 | 0 | 1];
  };

  it("was produced by NuGet's own library, over the real feed", () => {
    expect(oracle.generatedWith).toMatch(/^dotnet .* \/ NuGet\.Versioning 6\./);
    expect(oracle.feedVersions).toBeGreaterThan(11000);
    expect(oracle.feedRefusedByNuGet).toEqual([]);
    expect(oracle.adjacent.length + oracle.random.length).toBeGreaterThanOrEqual(5000);
  });

  it.each([["neighbours in NuGet's order"], ["random pairs"], ["the cases that are easy to get wrong"]])("agrees on %s", (which) => {
    const pairs = which.startsWith("neighbours") ? oracle.adjacent : which.startsWith("random") ? oracle.random : oracle.handpicked;
    const wrong: string[] = [];
    for (const pair of pairs) {
      const [a, b, expected] = split(pair);
      const ours = compareNuget(a, b);
      // Antisymmetry too, or sorting by it is not well defined.
      const back = compareNuget(b, a);
      if (ours !== expected || back !== -expected) wrong.push(`${a} vs ${b}: NuGet ${expected}, here ${ours}/${back}`);
    }
    expect(wrong.slice(0, 5)).toEqual([]);
  });

  it("reads every version in the feed, as NuGet does", () => {
    const text = [...oracle.adjacent, ...oracle.random].flatMap((p) => {
      const [a, b] = split(p);
      return [a, b];
    });
    expect(text.filter((v) => parseNugetVersion(v) === null)).toEqual([]);
  });

  it("refuses what NuGet refuses", () => {
    expect(oracle.refused.length).toBeGreaterThan(20);
    for (const v of oracle.refused) {
      expect(compareNuget(v, "1.0"), JSON.stringify(v)).toBeNull();
      expect(compareNuget("1.0", v), JSON.stringify(v)).toBeNull();
    }
  });

  it("lowercases every package name in the feed exactly as .NET's ToLowerInvariant does", () => {
    expect(oracle.nameFold.length).toBeGreaterThan(1400);
    const wrong = oracle.nameFold.filter(([name, lower]) => normalizeName("nuget", name) !== lower);
    expect(wrong.slice(0, 5)).toEqual([]);
  });
});

describe("compareNuget: the rules that make it NuGet", () => {
  it.each([
    ["1", "1.0.0.0", 0],
    ["1.0", "1.0.0", 0],
    ["1.0.0", "1.0.0.0", 0],
    ["1.0.0.1", "1.0.0", 1],
    ["1.0.0.10", "1.0.0.9", 1],
    ["10.02.0", "10.2.0", 0], // leading zeros in the numeric parts are read as numbers
    ["1.2.6.62716-preview", "1.2.6.62716", -1],
    ["1.0.0-rc", "1.0.0-RC", 0], // text labels compare without regard to case
    ["1.0.0-alpha", "1.0.0-Beta", -1],
    ["1.0.0-alpha.1", "1.0.0-alpha.beta", -1], // a number sorts below text
    ["1.0.0-alpha.10", "1.0.0-alpha.2", 1], // numbers compare as numbers
    ["1.0.0-alpha", "1.0.0-alpha.1", -1], // a shorter list sorts below a longer one
    ["1.0.0-rc", "1.0.0", -1], // any prerelease sorts below the release
    ["1.0.0+build", "1.0.0", 0], // build metadata is ignored
    ["1.0.0+a", "1.0.0+b", 0],
    ["1.0.0-rc+a", "1.0.0-rc", 0],
    ["1.0.0--a", "1.0.0-a", -1], // the hyphen is a character of a label
    ["1.0.0-a-b", "1.0.0-a.b", 1],
  ] as const)("%s vs %s is %i", (a, b, expected) => {
    expect(compareNuget(a, b)).toBe(expected);
    expect(compareNuget(b, a)).toBe(expected === 0 ? 0 : -expected);
  });

  it("orders a numeric prerelease label above Int32 exactly, as NuGet does, but refuses a numeric part that large", () => {
    expect(compareNuget("1.0.0-99999999999999999999", "1.0.0-99999999999999999998")).toBe(1);
    expect(compareNuget("2147483647.0.0", "2147483646.0.0")).toBe(1);
    for (const v of ["2147483648.0.0", "1.2147483648.0", "1.0.2147483648", "1.0.0.2147483648", "99999999999.0.0"]) expect(parseNugetVersion(v), v).toBeNull();
  });

  it("refuses a numeric prerelease label with a leading zero, and nothing else about zeros", () => {
    for (const v of ["1.0.0-01", "1.0.0-a.01", "1.0.0-00"]) expect(parseNugetVersion(v), v).toBeNull();
    for (const v of ["1.0.0-0", "1.0.0-0251-40", "1.0.0-a.0", "1.0.0-a01", "03.02.01"]) expect(parseNugetVersion(v), v).not.toBeNull();
  });

  it.each(["", " ", "abc", "v1.0", "1.0.0.0.0", "1.0.0.", ".1.0", "1..0", "1.0.0-", "1.0.0+", "1.0.0-a..b", "1.-1.0", "1.0.0-a_b", "1.0.0 beta", "1.0.0-é", "１.０"])("refuses %j", (v) => {
    expect(parseNugetVersion(v)).toBeNull();
  });

  it("refuses surrounding whitespace, which NuGet would trim", () => {
    for (const v of [" 1.0.0", "1.0.0 ", "1.0.0\n", "\t1.0.0"]) expect(parseNugetVersion(v), JSON.stringify(v)).toBeNull();
  });

  it("is what compareVersions uses for nuget", () => {
    expect(compareVersions("nuget", "1.0.0-rc", "1.0.0")).toBe(-1);
    expect(compareVersions("nuget", "1.0.0.0.0", "1.0")).toBeNull();
  });
});

describe("parseNugetUrl: the flat container", () => {
  it("reads id, version and file, which all say the same thing", () => {
    expect(parse(flat("newtonsoft.json", "13.0.3"))).toEqual([pkg("newtonsoft.json", "13.0.3")]);
  });
  it("keeps a prerelease and a four-part version", () => {
    expect(parse(flat("serilog", "3.1.0-rc.1"))).toEqual([pkg("serilog", "3.1.0-rc.1")]);
    expect(parse(flat("fody", "6.8.5.1001"))).toEqual([pkg("fody", "6.8.5.1001")]);
  });
  it("compares the file name without regard to case, as the flat container lowercases it", () => {
    expect(parse(flat("newtonsoft.json", "13.0.3", "Newtonsoft.Json.13.0.3.NUPKG"))).toEqual([pkg("newtonsoft.json", "13.0.3")]);
    expect(parse("https://api.nuget.org/v3-flatcontainer/Newtonsoft.Json/13.0.3/newtonsoft.json.13.0.3.nupkg")).toEqual([pkg("Newtonsoft.Json", "13.0.3")]);
  });
  it("reads a Unicode id, which the feed's look-alike malware uses", () => {
    const id = "2captcһaapі";
    expect(parse(`https://api.nuget.org/v3-flatcontainer/${encodeURIComponent(id)}/1.10.1/${encodeURIComponent(id)}.1.10.1.nupkg`)).toEqual([pkg(id, "1.10.1")]);
  });
  it("tolerates a mirror's path prefix and ignores the query", () => {
    expect(parse(`https://mirror.example.com/artifactory/api/nuget/v3/nuget-remote/flat2/serilog/3.1.0/serilog.3.1.0.nupkg?x=1`)).toEqual([pkg("serilog", "3.1.0")]);
  });
  it("requires the file name to be exactly {id}.{version}.nupkg", () => {
    expect(parse(flat("serilog", "3.1.0", "serilog.3.1.1.nupkg"))).toEqual([]);
    expect(parse(flat("serilog", "3.1.0", "other.3.1.0.nupkg"))).toEqual([]);
    expect(parse(flat("serilog", "3.1.0", "serilog.3.1.0.nupkg.sha512"))).toEqual([]);
    expect(parse(flat("serilog", "3.1.0", "serilog.3.1.0.nuspec"))).toEqual([]);
  });
  it("accepts an id at the length limit and refuses one beyond it", () => {
    const ok = "a".repeat(100);
    expect(parse(flat(ok, "1.0.0"))).toEqual([pkg(ok, "1.0.0")]);
    expect(parse(flat(`${ok}b`, "1.0.0"))).toEqual([]);
  });
  it.each([
    "https://api.nuget.org/v3-flatcontainer/serilog/index.json",
    "https://api.nuget.org/v3/index.json",
    "https://www.nuget.org/api/v2/package/Serilog/3.1.0",
    "https://www.nuget.org/packages/Serilog/3.1.0",
    "https://api.nuget.org/v3-flatcontainer/ser..ilog/3.1.0/ser..ilog.3.1.0.nupkg",
    "https://api.nuget.org/v3-flatcontainer/-x/3.1.0/-x.3.1.0.nupkg",
    "https://api.nuget.org/v3-flatcontainer/ser%2Filog/3.1.0/ser%2Filog.3.1.0.nupkg",
    "https://api.nuget.org/v3-flatcontainer/%E0%A4%A/3.1.0/x.3.1.0.nupkg",
    "https://api.nuget.org/v3-flatcontainer/serilog/latest/serilog.latest.nupkg",
    "https://api.nuget.org/v3-flatcontainer//3.1.0/.3.1.0.nupkg",
    "https://example.com/serilog.3.1.0.nupkg",
    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
  ])("is not a download: %s", (url) => expect(parse(url)).toEqual([]));
});

describe("parseNugetUrl: the CDN the legacy v2 endpoint redirects to", () => {
  const cdn = (file: string, host = "https://globalcdn.nuget.org/packages") => parse(`${host}/${file}?packageVersion=x`);
  const reading = (found: ReturnType<typeof parse>, name: string, version: string) => found.find((f) => f.name === name && f.version === version);

  it("returns the real reading first, and the others after it", () => {
    const found = cdn("newtonsoft.json.13.0.3.nupkg");
    expect(found[0]).toEqual(pkg("newtonsoft.json", "13.0.3"));
    // The same file name is also id `newtonsoft.json.13` at version `0.3`, and id `newtonsoft.json.13.0` at `3`.
    expect(found).toEqual([pkg("newtonsoft.json", "13.0.3"), pkg("newtonsoft.json.13", "0.3"), pkg("newtonsoft.json.13.0", "3")]);
  });
  it("keeps a prerelease label that itself contains a dot", () => {
    expect(reading(cdn("serilog.3.1.0-rc.1.nupkg"), "serilog", "3.1.0-rc.1")).toBeDefined();
    expect(reading(cdn("fody.6.8.5.1001-preview.nupkg"), "fody", "6.8.5.1001-preview")).toBeDefined();
  });
  it("finds an id with a digit in it, and one that ends in a number", () => {
    expect(cdn("log4net.2.0.8.nupkg")[0]).toEqual(pkg("log4net", "2.0.8"));
    // `foo.1` at 2.0.0 and `foo` at 1.2.0.0 are the same file name: both readings are offered.
    const found = cdn("foo.1.2.0.0.nupkg");
    expect(reading(found, "foo", "1.2.0.0")).toBeDefined();
    expect(reading(found, "foo.1", "2.0.0")).toBeDefined();
  });
  it("is blocked through the path the filter takes: parse, look up each reading, take the worst", () => {
    const entry = buildKvEntry(distillFor(record("nuget-MAL-2024-11505.json"), ["nuget"]), "2026-11-09T00:00:00Z") as KvEntry;
    const index = new Map<string, KvEntry>([[kvKey("nuget", "bunifu.form") ?? "", entry]]);
    const decide = (file: string) =>
      cdn(file).map((p) => {
        const hit = index.get(kvKey("nuget", p.name) ?? "");
        return { name: p.name, version: p.version, outcome: hit ? summarizeVerdict(evaluate("nuget", hit, p.version)).outcome : "allowed" };
      });
    expect(decide("bunifu.form.1.0.5.nupkg").map((r) => r.outcome)).toContain("blocked");
    expect(decide("bunifu.form.9.9.9.nupkg").map((r) => r.outcome)).not.toContain("blocked");
  });
  it("tolerates a mirror's host and path prefix, and is case-insensitive about the segment and extension", () => {
    expect(parse("https://mirror.example.com/artifactory/api/nuget/repo/packages/serilog.3.1.0.nupkg")[0]).toEqual(pkg("serilog", "3.1.0"));
    expect(parse("https://globalcdn.nuget.org/Packages/serilog.3.1.0.NUPKG")[0]).toEqual(pkg("serilog", "3.1.0"));
  });
  it("keeps at most eight readings, the leftmost", () => {
    // Each `1-a` token is a version with a prerelease, so every split is a valid reading.
    const found = cdn(`a.${Array(10).fill("1-a").join(".")}.nupkg`);
    expect(found).toHaveLength(8);
    expect(found[0]?.name).toBe("a");
  });
  it("accepts an id at the length limit and refuses one beyond it", () => {
    const ok = "a".repeat(100);
    expect(cdn(`${ok}.1.0.0.nupkg`)[0]).toEqual(pkg(ok, "1.0.0"));
    expect(cdn(`${ok}b.1.0.0.nupkg`).map((f) => f.name)).not.toContain(`${ok}b`);
  });
  it("offers a harmless reading for a file name that is also a valid id and version", () => {
    // A numeric id is legal, and `serilog.1` at 0.0.0.0 is too: these cost a lookup, and cannot outvote a real package.
    expect(cdn("3.1.0.nupkg").map((f) => f.name)).toEqual(["3", "3.1"]);
    expect(cdn("serilog.1.0.0.0.0.nupkg")[0]).toEqual(pkg("serilog.1", "0.0.0.0"));
  });
  it.each([
    "https://globalcdn.nuget.org/packages/serilog.nupkg",
    "https://globalcdn.nuget.org/packages/serilog.latest.nupkg",
    "https://globalcdn.nuget.org/packages/.3.1.0.nupkg",
    "https://globalcdn.nuget.org/packages/serilog.3.1.0.nupkg.sha512",
    "https://globalcdn.nuget.org/packages/serilog.3.1.0.nuspec",
    "https://globalcdn.nuget.org/other/serilog.3.1.0.nupkg",
    "https://globalcdn.nuget.org/serilog.3.1.0.nupkg",
    "https://globalcdn.nuget.org/packages/ser%2Filog.3.1.0.nupkg",
    "https://globalcdn.nuget.org/packages/%E0%A4%A.3.1.0.nupkg",
  ])("is not a download: %s", (url) => expect(parse(url)).toEqual([]));
});

describe("NuGet names", () => {
  it("fold case and nothing else", () => {
    expect(normalizeName("nuget", "  Newtonsoft.Json ")).toBe("newtonsoft.json");
    expect(kvKey("nuget", "A.B_c")).toBe("nuget:a.b_c");
    expect(kvKey("nuget", "a.b-c")).not.toBe(kvKey("nuget", "a.b_c"));
  });
  it("write a package URL of type nuget, lowercased", () => {
    expect(toPurl({ ecosystem: "nuget", namespace: null, name: "Newtonsoft.Json", version: "13.0.3" })).toBe("pkg:nuget/newtonsoft.json@13.0.3");
  });
});

describe("real NuGet advisories", () => {
  const entryFor = (file: string, name: string): KvEntry => {
    const rows = distillFor(record(file), ["nuget"]).filter((r) => r.packageName === name);
    return buildKvEntry(rows, "2026-11-09T00:00:00Z") as KvEntry;
  };
  const outcome = (entry: KvEntry, version: string) => summarizeVerdict(evaluate("nuget", entry, version)).outcome;

  describe("MAL-2024-11505, a mixed-case id", () => {
    const mal = record("nuget-MAL-2024-11505.json");
    it("is malware, filed under the lowercase id", () => {
      expect(classify(mal)).toBe("malware");
      expect(distillFor(mal, ["nuget"]).map((r) => r.packageName)).toEqual(["bunifu.form"]);
    });
    it("is stopped from a URL a client wrote in lowercase, though OSV spells the id `Bunifu.Form`", () => {
      const [found] = parse(flat("bunifu.form", "1.0.5"));
      expect(found).toBeDefined();
      expect(outcome(entryFor("nuget-MAL-2024-11505.json", "bunifu.form"), found!.version)).toBe("blocked");
      expect(outcome(entryFor("nuget-MAL-2024-11505.json", "bunifu.form"), "9.9.9")).toBe("allowed");
    });
  });

  describe("MAL-2024-3991, an id spelled with Cyrillic look-alikes", () => {
    it("is blocked by the id the client sends, percent-encoded and lowercased", () => {
      const id = "2captcһaapі";
      const [found] = parse(`https://api.nuget.org/v3-flatcontainer/${encodeURIComponent(id)}/1.10.1/${encodeURIComponent(id)}.1.10.1.nupkg`);
      expect(kvKey("nuget", found!.name)).toBe(`nuget:${id}`);
      const entry = entryFor("nuget-MAL-2024-3991.json", id);
      expect(entry.m.map((m) => m.id)).toEqual(["MAL-2024-3991"]);
      expect(outcome(entry, found!.version)).toBe("blocked");
    });
    it("is not confused with the Latin spelling", () => {
      expect(normalizeName("nuget", "2captchaapi")).not.toBe(normalizeName("nuget", "2captcһaapі"));
    });
  });

  describe("GHSA-2rvx-cvfc-mcp2 (NewRelic.Agent), whose fixed boundary has four parts", () => {
    const [row] = distillFor(record("nuget-GHSA-2rvx-cvfc-mcp2.json"), ["nuget"]);
    const affected = (v: string) => isVersionAffected("nuget", row!.spec, v);
    it("matches below the fixed version, and not from it up", () => {
      expect(["5.0.0", "6.3.122.0", "6.3.122.9999"].map(affected)).toEqual([true, true, true]);
      expect(["6.3.123", "6.3.123.0", "6.3.124.0", "7.0.0"].map(affected)).toEqual([false, false, false, false]);
    });
    it("was inert under the SemVer comparator, which is why this exists", async () => {
      const { compareSemver } = await import("../src/index.js");
      expect(compareSemver("6.3.123.0", "6.3.123.0")).toBeNull();
    });
  });

  describe("GHSA-28xm-prxc-5866, one record naming two ids", () => {
    it("gives each its own row, and bounds a prerelease range", () => {
      const rows = distillFor(record("nuget-GHSA-28xm-prxc-5866.json"), ["nuget"]);
      expect(rows.map((r) => r.packageName).sort()).toEqual(["opentelemetry.resources.aws", "opentelemetry.sampler.aws"]);
      const sampler = rows.find((r) => r.packageName === "opentelemetry.sampler.aws")!;
      expect(["0.1.0-alpha.1", "0.1.0-alpha.7"].map((v) => isVersionAffected("nuget", sampler.spec, v))).toEqual([true, true]);
      expect(["0.1.0-alpha.8", "0.1.0-beta", "0.1.0"].map((v) => isVersionAffected("nuget", sampler.spec, v))).toEqual([false, false, false]);
    });
  });

  it("flags a vulnerability and blocks nothing", () => {
    const entry = entryFor("nuget-GHSA-2rvx-cvfc-mcp2.json", "newrelic.agent");
    expect(outcome(entry, "6.3.122.0")).toBe("flagged");
    expect(outcome(entry, "6.3.123.0")).toBe("allowed");
  });
});

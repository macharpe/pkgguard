import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildKvEntry,
  classify,
  compareGem,
  compareVersions,
  distillFor,
  evaluate,
  isVersionAffected,
  kvKey,
  normalizeName,
  parseGemVersion,
  parseRubygemsUrl,
  summarizeVerdict,
  toPurl,
  type KvEntry,
  type OsvRecord,
} from "../src/index.js";

const FIXTURES = join(import.meta.dirname, "fixtures");
const record = (name: string): OsvRecord => JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as OsvRecord;
const parse = (url: string) => parseRubygemsUrl(new URL(url));
const gem = (name: string, version: string) => ({ ecosystem: "rubygems", namespace: null, name, version });

describe("compareGem against Ruby's own Gem::Version", () => {
  // Produced by scripts/oracles/gem-version.rb, which asks Ruby about the real feed's version strings. Ruby is not
  // needed to run this: the answers are committed.
  const oracle = JSON.parse(readFileSync(join(FIXTURES, "gem-version-oracle.json"), "utf8")) as {
    generatedWith: string;
    feedVersions: number;
    adjacent: string[];
    random: string[];
    handpicked: string[];
    refused: string[];
  };
  const sign = (c: string): -1 | 0 | 1 => Number(c) as -1 | 0 | 1;
  const split = (pair: string): [string, string, -1 | 0 | 1] => {
    const [b, c] = [pair.lastIndexOf("|"), pair.length];
    const rest = pair.slice(0, b);
    const mid = rest.indexOf("|");
    return [rest.slice(0, mid), rest.slice(mid + 1), sign(pair.slice(b + 1, c))];
  };

  it("was produced by a real Ruby, over the real feed", () => {
    // Not the old RubyGems on a system Ruby: before 3.1 `<=>` compared raw segments and disagrees on prereleases after a zero.
    expect(oracle.generatedWith).toMatch(/^ruby \d.* \/ rubygems v3\.[5-9]/);
    expect(oracle.feedVersions).toBeGreaterThan(6000);
    expect(oracle.adjacent.length + oracle.random.length).toBeGreaterThanOrEqual(5000);
  });

  it.each([["neighbours in Ruby's order"], ["random pairs"], ["the cases that are easy to get wrong"]])("agrees on %s", (which) => {
    const pairs = which.startsWith("neighbours") ? oracle.adjacent : which.startsWith("random") ? oracle.random : oracle.handpicked;
    const wrong: string[] = [];
    for (const pair of pairs) {
      const [a, b, expected] = split(pair);
      const ours = compareGem(a, b);
      // The relation must also be antisymmetric, or sorting by it is not well defined.
      const back = compareGem(b, a);
      if (ours !== expected || back !== -expected) wrong.push(`${a} vs ${b}: Ruby ${expected}, here ${ours}/${back}`);
    }
    expect(wrong.slice(0, 5)).toEqual([]);
  });

  it("refuses what Ruby refuses, and a blank string, which Ruby reads as zero but a download never has", () => {
    for (const v of oracle.refused) {
      expect(compareGem(v, "1.0"), JSON.stringify(v)).toBeNull();
      expect(compareGem("1.0", v), JSON.stringify(v)).toBeNull();
    }
  });
});

describe("compareGem: the rules that make it Gem::Version", () => {
  it.each([
    ["1.0", "1", 0],
    ["1.0.0", "1.0", 0],
    ["1.0.0.0", "1", 0],
    ["1.0.0.pre", "1.0.0", -1],
    ["1.0.0.pre", "1.0.0.rc1", -1],
    ["1.0.0.rc1", "1.0.0.rc2", -1],
    ["1.0.0.rc10", "1.0.0.rc2", 1], // "rc10" is split into "rc" and 10, so the number compares as a number
    ["1.0-rc1", "1.0.pre.rc1", 0], // a hyphen is read as ".pre."
    ["1.10", "1.9", 1],
    ["2.2.8", "2.2.8.1", -1],
    ["1.0.A", "1.0.a", -1], // Ruby compares letters case-sensitively
  ] as const)("%s vs %s is %i", (a, b, expected) => {
    expect(compareGem(a, b)).toBe(expected);
    expect(compareGem(b, a)).toBe(expected === 0 ? 0 : -expected);
  });
  it("orders integers above 2^53 exactly, as Ruby's bignums do", () => {
    expect(compareGem("1.99999999999999999999", "1.99999999999999999998")).toBe(1);
    expect(compareGem("99999999999999999999", "99999999999999999999")).toBe(0);
    expect(compareGem("9007199254740993", "9007199254740992")).toBe(1);
  });
  it.each(["", "  ", "abc", "v1.0", "1.0.", ".1", "1..0", "1_0", "1.0+1", "1.0 1"])("refuses %j", (v) => {
    expect(parseGemVersion(v)).toBeNull();
  });
  it("tolerates surrounding ASCII whitespace, as Ruby does", () => {
    expect(compareGem(" 1.0 ", "1.0")).toBe(0);
    expect(compareGem("1.0\t\n", "1.0")).toBe(0);
  });
  it("does not tolerate the non-ASCII spaces JavaScript's \\s would, which Ruby's does not", () => {
    for (const space of ["\u00a0", "\u2003", "\u3000", "\ufeff"]) {
      expect(parseGemVersion(`1.0${space}`), JSON.stringify(space)).toBeNull();
      expect(parseGemVersion(`${space}1.0`), JSON.stringify(space)).toBeNull();
    }
  });
  it("is what compareVersions uses for rubygems", () => {
    expect(compareVersions("rubygems", "1.0.0.pre", "1.0.0")).toBe(-1);
    expect(compareVersions("rubygems", "abc", "1.0")).toBeNull();
  });
});

describe("parseRubygemsUrl: the file name, and every way to read it", () => {
  it("reads what the gem client requests, measured behind Gateway", () => {
    expect(parse("https://rubygems.org/gems/rake-13.0.6.gem")).toEqual([gem("rake", "13.0.6")]);
  });
  it("keeps a hyphenated name", () => {
    expect(parse("https://rubygems.org/gems/rack-test-2.1.0.gem")).toEqual([gem("rack-test", "2.1.0")]);
    expect(parse("https://rubygems.org/gems/net-http-0.4.1.gem")).toEqual([gem("net-http", "0.4.1")]);
  });
  it("keeps the name's spelling, case included", () => {
    expect(parse("https://rubygems.org/gems/Rake-13.0.6.gem")).toEqual([gem("Rake", "13.0.6")]);
  });
  it("drops the platform, which is not part of what an advisory names", () => {
    expect(parse("https://rubygems.org/gems/nokogiri-1.16.2-x86_64-linux.gem")).toEqual([gem("nokogiri", "1.16.2")]);
    expect(parse("https://rubygems.org/gems/nokogiri-1.16.2-java.gem")).toEqual([gem("nokogiri", "1.16.2")]);
    expect(parse("https://rubygems.org/gems/ffi-1.16.3-x64-mingw-ucrt.gem")).toEqual([gem("ffi", "1.16.3")]);
  });
  it("keeps prerelease versions, which the file name writes with dots", () => {
    expect(parse("https://rubygems.org/gems/rails-7.0.0.rc1.gem")).toEqual([gem("rails", "7.0.0.rc1")]);
    expect(parse("https://rubygems.org/gems/foo-1.0.0.pre.1.gem")).toEqual([gem("foo", "1.0.0.pre.1")]);
  });
  it("tolerates a mirror's path prefix, ignores the query, and decodes percent-escapes", () => {
    expect(parse("https://mirror.example.com/artifactory/api/gems/gems-remote/gems/rake-13.0.6.gem")).toEqual([gem("rake", "13.0.6")]);
    expect(parse("https://rubygems.org/gems/rake-13.0.6.gem?x=1#frag")).toEqual([gem("rake", "13.0.6")]);
    expect(parse("https://rubygems.org/gems/ra%6Be-13.0.6.gem")).toEqual([gem("rake", "13.0.6")]);
  });

  describe("a name that ends in something that looks like a version", () => {
    // Three malware gems in OSV's feed are named like this (gemxy-1778522681, southnews-test-35329, zztemp-ssf-2605),
    // so a parser that took the first version-looking token would look up the wrong name for exactly the packages
    // that matter.
    it("returns both readings, the real one among them", () => {
      const found = parse("https://rubygems.org/gems/gemxy-1778522681-0.0.1.gem");
      expect(found).toEqual([gem("gemxy", "1778522681"), gem("gemxy-1778522681", "0.0.1")]);
    });
    it.each([
      ["southnews-test-35329", "0.0.1"],
      ["zztemp-ssf-2605", "0.0.1"],
    ])("finds %s", (name, version) => {
      expect(parse(`https://rubygems.org/gems/${name}-${version}.gem`)).toContainEqual(gem(name, version));
    });
  });

  describe("a platform that ends in a number", () => {
    it("returns the reading with the right name first, and the wrong one as well", () => {
      const found = parse("https://rubygems.org/gems/google-protobuf-3.25.3-x86_64-darwin-19.gem");
      expect(found[0]).toEqual(gem("google-protobuf", "3.25.3"));
      expect(found).toContainEqual(gem("google-protobuf-3.25.3-x86_64-darwin", "19"));
    });
  });

  it("keeps at most eight readings, the rightmost, so a platform-less file is always among them", () => {
    const found = parse("https://rubygems.org/gems/a-1-2-3-4-5-6-7-8-9-10-11-12.gem");
    expect(found).toHaveLength(8);
    expect(found.at(-1)).toEqual(gem("a-1-2-3-4-5-6-7-8-9-10-11", "12"));
  });

  it("is not a download when any path segment has a malformed escape, even one that is only a prefix", () => {
    expect(parse("https://mirror.example.com/%E0%A4%A/gems/rake-13.0.6.gem")).toEqual([]);
    expect(parse("https://mirror.example.com/ok/gems/rake-13.0.6.gem")).toEqual([gem("rake", "13.0.6")]);
  });

  it.each([
    "https://rubygems.org/gems/rake",
    "https://rubygems.org/gems/rake-13.0.6.gemspec",
    "https://rubygems.org/gems/rake-13.0.6.gem.sig",
    "https://rubygems.org/quick/Marshal.4.8/rake-13.0.6.gemspec.rz",
    "https://rubygems.org/specs.4.8.gz",
    "https://index.rubygems.org/versions",
    "https://rubygems.org/downloads/rake-13.0.6.gem",
    "https://rubygems.org/rake-13.0.6.gem",
    "https://rubygems.org/gems/13.0.6.gem",
    "https://rubygems.org/gems/-1.0.gem",
    "https://rubygems.org/gems/.gem",
    "https://rubygems.org/gems/rake-latest.gem",
    "https://rubygems.org/gems/rake-.gem",
    "https://rubygems.org/gems/ra%2Fke-1.0.gem",
    "https://rubygems.org/gems/%E0%A4%A-1.0.gem",
    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
  ])("is not a download: %s", (url) => expect(parse(url)).toEqual([]));
});

describe("RubyGems names", () => {
  it("fold case and nothing else: `-` and `_` are different gems", () => {
    expect(normalizeName("rubygems", "  Rack ")).toBe("rack");
    expect(kvKey("rubygems", "3scale-time-range")).toBe("rubygems:3scale-time-range");
    expect(kvKey("rubygems", "3scale-time_range")).toBe("rubygems:3scale-time_range");
    expect(kvKey("rubygems", "3scale-time-range")).not.toBe(kvKey("rubygems", "3scale-time_range"));
  });
  it("write a package URL of type gem", () => {
    expect(toPurl({ ecosystem: "rubygems", namespace: null, name: "Rails", version: "7.0.0" })).toBe("pkg:gem/rails@7.0.0");
  });
});

describe("real RubyGems advisories", () => {
  const entryFor = (file: string, name: string): KvEntry => {
    const rows = distillFor(record(file), ["rubygems"]).filter((r) => r.packageName === name);
    return buildKvEntry(rows, "2026-11-09T00:00:00Z") as KvEntry;
  };
  const outcome = (entry: KvEntry, version: string) => summarizeVerdict(evaluate("rubygems", entry, version)).outcome;

  describe("MAL-2026-7711, whose name ends in a version-looking token", () => {
    const mal = record("rubygems-MAL-2026-7711.json");
    it("is malware, found by its own id", () => {
      expect(classify(mal)).toBe("malware");
      expect(distillFor(mal, ["rubygems"]).map((r) => r.packageName)).toEqual(["gemxy-1778522681"]);
    });
    it("is stopped through the path the filter takes: parse the URL, look up each reading, take the worst", () => {
      const index = new Map<string, KvEntry>([["rubygems:gemxy-1778522681", entryFor("rubygems-MAL-2026-7711.json", "gemxy-1778522681")]]);
      const decide = (url: string) =>
        parse(url).map((pkg) => {
          const entry = index.get(kvKey("rubygems", `${pkg.name}`) ?? "");
          return { name: pkg.name, version: pkg.version, outcome: entry ? outcome(entry, pkg.version) : "allowed" };
        });
      const readings = decide("https://rubygems.org/gems/gemxy-1778522681-0.0.1.gem");
      expect(readings).toEqual([
        { name: "gemxy", version: "1778522681", outcome: "allowed" }, // the wrong reading: no such gem in the index
        { name: "gemxy-1778522681", version: "0.0.1", outcome: "blocked" },
      ]);
      // Another version of the same gem is not listed, so it is not stopped.
      expect(decide("https://rubygems.org/gems/gemxy-1778522681-9.9.9.gem").map((r) => r.outcome)).toEqual(["allowed", "allowed"]);
    });
  });

  describe("GHSA-22f2-v57c-j9cx (rack), whose fixed boundary has four parts", () => {
    const [row] = distillFor(record("rubygems-GHSA-22f2-v57c-j9cx.json"), ["rubygems"]).filter((r) => r.packageName === "rack");
    const affected = (v: string) => isVersionAffected("rubygems", row!.spec, v);
    it("matches below the fixed version, and a trailing zero changes nothing", () => {
      expect(["0.4", "1.0.0", "2.2.7", "2.2.8", "2.2.8.0", "3.0.0"].map(affected)).toEqual([true, true, true, true, true, true]);
    });
    it("does not match from the fixed version up, or below the first introduced one", () => {
      expect(["0.3", "2.2.8.1", "2.2.8.2", "2.2.9"].map(affected)).toEqual([false, false, false, false]);
    });
    it("was inert under the SemVer comparator, which is why this exists", async () => {
      const { compareSemver } = await import("../src/index.js");
      expect(compareSemver("2.2.8.1", "2.2.8.1")).toBeNull();
    });
  });

  describe("GHSA-29gr-w57f-rpfw (actionpack), bounded by prereleases", () => {
    const [row] = distillFor(record("rubygems-GHSA-29gr-w57f-rpfw.json"), ["rubygems"]).filter((r) => r.packageName === "actionpack");
    const affected = (v: string) => isVersionAffected("rubygems", row!.spec, v);
    it("matches the prereleases from beta1 up to, not including, beta3", () => {
      expect(["4.2.0.beta1", "4.2.0.beta2"].map(affected)).toEqual([true, true]);
      expect(["4.2.0.beta3", "4.2.0", "4.2.0.rc1"].map(affected)).toEqual([false, false, false]);
    });
  });

  it("flags a vulnerability and blocks nothing", () => {
    const entry = entryFor("rubygems-GHSA-22f2-v57c-j9cx.json", "rack");
    expect(outcome(entry, "2.2.8")).toBe("flagged");
    expect(outcome(entry, "2.2.8.1")).toBe("allowed");
  });
});

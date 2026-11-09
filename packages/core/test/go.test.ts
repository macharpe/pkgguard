import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ECOSYSTEMS,
  buildKvEntry,
  classify,
  compareGo,
  compareVersions,
  distillFor,
  evaluate,
  isVersionAffected,
  kvKey,
  normalizeName,
  parseGoUrl,
  parseGoVersion,
  summarizeVerdict,
  toPurl,
  unescapeGoPath,
  type KvEntry,
  type OsvRecord,
} from "../src/index.js";

const FIXTURES = join(import.meta.dirname, "fixtures");
const record = (name: string): OsvRecord => JSON.parse(readFileSync(join(FIXTURES, name), "utf8")) as OsvRecord;
const parse = (url: string) => parseGoUrl(new URL(url));
const pkg = (name: string, version: string) => ({ ecosystem: "go", namespace: null, name, version });
const proxy = (path: string, file: string) => `https://proxy.golang.org/${path}/@v/${file}`;

const oracle = JSON.parse(readFileSync(join(FIXTURES, "go-version-oracle.json"), "utf8")) as {
  generatedWith: string;
  feedVersions: number;
  feedRefusedByGo: string[];
  adjacent: string[];
  random: string[];
  handpicked: string[];
  refused: string[];
  paths: Array<{ name: string; escaped: string; checkPath: boolean }>;
  unescapablePaths: string[];
  versionEscapes: Array<[string, string]>;
};

describe("compareGo against Go's own golang.org/x/mod/semver", () => {
  // Produced by scripts/oracles/go-version/, which asks Go about the real feed's version strings and module paths. Go is not
  // needed to run this: the answers are committed.
  const split = (pair: string): [string, string, -1 | 0 | 1] => {
    const last = pair.lastIndexOf("|");
    const rest = pair.slice(0, last);
    const mid = rest.indexOf("|");
    return [rest.slice(0, mid), rest.slice(mid + 1), Number(pair.slice(last + 1)) as -1 | 0 | 1];
  };

  it("was produced by Go's own library, over the real feed", () => {
    expect(oracle.generatedWith).toMatch(/^go go1\.\d+/);
    expect(oracle.feedVersions).toBeGreaterThan(3900);
    expect(oracle.adjacent.length + oracle.random.length).toBeGreaterThanOrEqual(5000);
  });

  it.each([["neighbours in Go's order"], ["random pairs"], ["the cases that are easy to get wrong"]])("agrees on %s", (which) => {
    const pairs = which.startsWith("neighbours") ? oracle.adjacent : which.startsWith("random") ? oracle.random : oracle.handpicked;
    const wrong: string[] = [];
    for (const pair of pairs) {
      const [a, b, expected] = split(pair);
      const ours = compareGo(a, b);
      const back = compareGo(b, a);
      if (ours !== expected || back !== -expected) wrong.push(`${a} vs ${b}: Go ${expected}, here ${ours}/${back}`);
    }
    expect(wrong.slice(0, 5)).toEqual([]);
  });

  it("refuses what Go refuses, and reads what Go reads", () => {
    expect(oracle.refused.length).toBeGreaterThan(20);
    // The oracle asked Go about `"v" + string`, so the probes are asked the same way: `v1.0.0` here is `vv1.0.0`.
    for (const probe of oracle.refused) {
      const v = `v${probe}`;
      expect(compareGo(v, "1.0.0"), JSON.stringify(v)).toBeNull();
      expect(compareGo("1.0.0", v), JSON.stringify(v)).toBeNull();
    }
    const refused = new Set(oracle.feedRefusedByGo);
    expect(refused.size).toBeGreaterThan(5);
    for (const v of refused) expect(parseGoVersion(v), v).toBeNull();
  });
});

describe("compareGo: the rules that make it Go", () => {
  it.each([
    ["1", "1.0.0", 0], // shorthand: `v1` is `v1.0.0`
    ["1.2", "1.2.0", 0],
    ["0.46", "0.46.0", 0],
    ["136", "136.0.0", 0],
    ["1.2", "1.2.1", -1],
    ["1.0.0+incompatible", "1.0.0", 0], // build metadata is ignored
    ["2.0.0+a", "2.0.0+b", 0],
    ["1.0.0-rc.10", "1.0.0-rc.2", 1],
    ["1.0.0-alpha", "1.0.0-alpha.1", -1],
    ["1.0.0-1", "1.0.0-a", -1], // a number sorts below text
    ["1.0.0-RC", "1.0.0-rc", -1], // text compares as ASCII: case matters here, unlike NuGet
    ["1.0.0-rc1", "1.0.0", -1],
    ["0.0.0-20210101000000-0123456789ab", "0.0.0-20210101000000-0123456789ac", -1],
    ["10.0.0", "9.0.0", 1],
    ["1.0.0-a-b", "1.0.0-a.b", 1],
  ] as const)("%s vs %s is %i", (a, b, expected) => {
    expect(compareGo(a, b)).toBe(expected);
    expect(compareGo(b, a)).toBe(expected === 0 ? 0 : -expected);
  });

  it("reads a version with or without the leading v, which the proxy writes and OSV does not", () => {
    expect(compareGo("v1.2.3", "1.2.3")).toBe(0);
    expect(compareGo("v1.2.3", "v1.2.4")).toBe(-1);
    expect(compareGo("vv1.2.3", "1.2.3")).toBeNull();
    expect(compareGo("v", "1.2.3")).toBeNull();
  });

  it("orders integers above 2^53 exactly", () => {
    expect(compareGo("99999999999999999999.0.0", "99999999999999999998.0.0")).toBe(1);
    expect(compareGo("1.0.0-99999999999999999999", "1.0.0-99999999999999999998")).toBe(1);
  });

  it("gives a shorthand version nowhere to hang a prerelease or a build", () => {
    for (const v of ["1.2-rc1", "1-rc1", "1+b", "1.0+b"]) expect(parseGoVersion(v), v).toBeNull();
    expect(parseGoVersion("1.2.0-rc1")).not.toBeNull();
  });

  it("refuses leading zeros in the numbers, but not in a build or in a text label", () => {
    for (const v of ["01.0.0", "1.02.0", "1.0.03", "1.0.0-01", "1.0.0-00"]) expect(parseGoVersion(v), v).toBeNull();
    for (const v of ["1.0.0-0", "1.0.0-a01", "1.0.0+001", "1.0.0-0a", "1.0.0+a-b", "1.0.0-a.b+c.d"]) expect(parseGoVersion(v), v).not.toBeNull();
  });

  it.each(["", "v", "1.", ".1", "1..0", "1.2.3.4", "1.0.0-", "1.0.0+", "1.0.0-a..b", "1.0.0-é", "1.0.0-a_b", "1.0.0+a..b", "1.0.0 ", " 1.0.0", "x.y.z", "1.0.0-a+b+c", "1.0.0+a_b", "1.0.0+é"])("refuses %j", (v) => {
    expect(parseGoVersion(v)).toBeNull();
  });

  it("is what compareVersions uses for go", () => {
    expect(compareVersions("go", "v1.0.0-rc1", "v1.0.0")).toBe(-1);
    expect(compareVersions("go", "1.2.3.4", "1.0.0")).toBeNull();
  });
});

describe("unescapeGoPath: the proxy's case encoding", () => {
  it("agrees with Go's own EscapePath over every module path in the feed", () => {
    expect(oracle.paths.length).toBeGreaterThan(1600);
    const wrong = oracle.paths.filter((p) => unescapeGoPath(p.escaped) !== p.name);
    expect(wrong.slice(0, 5)).toEqual([]);
    expect(oracle.paths.filter((p) => p.name !== p.escaped).length).toBeGreaterThan(50);
  });
  it("agrees with Go's own EscapeVersion on the versions that contain a capital", () => {
    expect(oracle.versionEscapes.length).toBeGreaterThan(3);
    for (const [version, escaped] of oracle.versionEscapes) expect(unescapeGoPath(escaped), escaped).toBe(version);
  });
  it.each(["!", "a!", "!A", "!1", "!!a", "a!-b", "GitHub.com/x", "github.com/Foo"])("refuses the bad encoding %j", (escaped) => {
    expect(unescapeGoPath(escaped)).toBeNull();
  });
  it("decodes each !x to the capital X", () => {
    expect(unescapeGoPath("github.com/!burnt!sushi/toml")).toBe("github.com/BurntSushi/toml");
    expect(unescapeGoPath("v2.0.0-!r!c1")).toBe("v2.0.0-RC1");
  });
});

describe("parseGoUrl: the module proxy", () => {
  it("reads module and version from a download", () => {
    expect(parse(proxy("github.com/foo/bar", "v1.2.3.zip"))).toEqual([pkg("github.com/foo/bar", "v1.2.3")]);
  });
  it("keeps a major-version suffix, a +incompatible build and a pseudo-version", () => {
    expect(parse(proxy("github.com/foo/bar/v2", "v2.1.0.zip"))).toEqual([pkg("github.com/foo/bar/v2", "v2.1.0")]);
    expect(parse(proxy("github.com/foo/bar", "v2.0.0+incompatible.zip"))).toEqual([pkg("github.com/foo/bar", "v2.0.0+incompatible")]);
    expect(parse(proxy("github.com/foo/bar", "v0.0.0-20210101000000-0123456789ab.zip"))).toEqual([pkg("github.com/foo/bar", "v0.0.0-20210101000000-0123456789ab")]);
  });
  it("decodes the capitals of the path and the version", () => {
    expect(parse(proxy("github.com/!burnt!sushi/toml", "v1.3.2.zip"))).toEqual([pkg("github.com/BurntSushi/toml", "v1.3.2")]);
    expect(parse(proxy("github.com/foo/bar", "v2.0.0-!r!c1.zip"))).toEqual([pkg("github.com/foo/bar", "v2.0.0-RC1")]);
  });
  it("reads every module path in the feed, through the escape Go itself writes", () => {
    const readable = oracle.paths.filter((p) => p.checkPath && ECOSYSTEMS.go.inScope?.(p.name));
    expect(readable.length).toBeGreaterThan(1500);
    const wrong = readable.filter((p) => parse(proxy(p.escaped, "v1.0.0.zip"))[0]?.name !== p.name);
    expect(wrong.map((p) => p.name).slice(0, 5)).toEqual([]);
  });
  it("tolerates a mirror's path prefix and ignores the query", () => {
    expect(parse("https://mirror.example.com/artifactory/api/go/go-remote/github.com/foo/bar/@v/v1.2.3.zip?x=1")).toEqual([pkg("github.com/foo/bar", "v1.2.3")]);
  });
  it("reads a module path that contains /packages/", () => {
    expect(parse(proxy("github.com/foo/packages/bar", "v0.0.0-20210101000000-0123456789ab.zip"))).toEqual([pkg("github.com/foo/packages/bar", "v0.0.0-20210101000000-0123456789ab")]);
  });
  it("is not what PyPI reads", () => {
    const url = new URL(proxy("github.com/foo/packages/bar", "v1.0.0.zip"));
    expect(ECOSYSTEMS.pypi.parse(url)).toEqual([]);
  });
  it.each([
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.info",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.mod",
    "https://proxy.golang.org/github.com/foo/bar/@v/list",
    "https://proxy.golang.org/github.com/foo/bar/@latest",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.zip.sha256",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.ZIP",
    "https://proxy.golang.org/github.com/foo/bar/v1.2.3.zip",
    "https://proxy.golang.org/@v/v1.2.3.zip",
    "https://proxy.golang.org/stdlib/@v/v1.2.3.zip",
    "https://proxy.golang.org/net/http/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/1.2.3.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.4.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/V1.2.3.zip",
    "https://proxy.golang.org/github.com/Foo/bar/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/!/bar/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3-RC1.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.02.3.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3-01.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3-a..b.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3+a_b.zip",
    "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3x.zip",
    "https://proxy.golang.org/github.com/foo//bar/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/.foo/bar/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/foo./bar/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/f%2Foo/bar/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/f%E0%A4%A/bar/@v/v1.2.3.zip",
    "https://proxy.golang.org/github.com/foo bar/@v/v1.2.3.zip",
    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
  ])("is not a download: %s", (url) => expect(parse(url)).toEqual([]));
  it("caps override names at the length the parser accepts", () => {
    expect(ECOSYSTEMS.go.maxNameLength).toBe(255);
  });
  it("refuses a module path over the length limit", () => {
    const long = `github.com/${"a".repeat(244)}`;
    expect(parse(proxy(long, "v1.0.0.zip"))).toEqual([pkg(long, "v1.0.0")]);
    expect(parse(proxy(`${long}b`, "v1.0.0.zip"))).toEqual([]);
  });
});

describe("Go names", () => {
  it("are case-sensitive: two modules that differ only by case stay two", () => {
    expect(normalizeName("go", "  github.com/BurntSushi/toml ")).toBe("github.com/BurntSushi/toml");
    expect(kvKey("go", "github.com/bishopfox/sliver")).toBe("go:github.com/bishopfox/sliver");
    expect(kvKey("go", "github.com/BishopFox/sliver")).toBe("go:github.com/BishopFox/sliver");
    expect(kvKey("go", "github.com/bishopfox/sliver")).not.toBe(kvKey("go", "github.com/BishopFox/sliver"));
  });
  it("write a package URL of type golang that keeps the path's slashes and its case", () => {
    expect(toPurl({ ecosystem: "go", namespace: null, name: "github.com/BurntSushi/toml", version: "v1.3.2" })).toBe("pkg:golang/github.com/BurntSushi/toml@v1.3.2");
    expect(toPurl({ ecosystem: "npm", namespace: "@babel", name: "core", version: "7.0.0" })).toBe("pkg:npm/%40babel/core@7.0.0");
  });
  it("are only stored when the first path element is a domain", () => {
    const spec = ECOSYSTEMS.go;
    for (const name of ["github.com/foo/bar", "gopkg.in/yaml.v3", "k8s.io/api"]) expect(spec.inScope?.(name), name).toBe(true);
    for (const name of ["stdlib", "toolchain", "net/http", "https://github.com/x/y", "sftpgo", "Traefik", ""]) expect(spec.inScope?.(name), name).toBe(false);
  });
  it("drop what a proxy cannot serve when a record is distilled", () => {
    const rec: OsvRecord = {
      id: "GO-2099-0001",
      modified: "2026-01-01T00:00:00Z",
      affected: ["github.com/foo/bar", "stdlib", "toolchain", "https://github.com/x/y", "net/http"].map((name) => ({ package: { ecosystem: "Go", name }, versions: ["1.0.0"] })),
    };
    expect(distillFor(rec, ["go"]).map((r) => r.packageName)).toEqual(["github.com/foo/bar"]);
  });
  it("accept every module path in the feed that Go's own CheckPath accepts, as override names", () => {
    const wrong = oracle.paths.filter((p) => p.checkPath && !ECOSYSTEMS.go.overrideNamePattern.test(p.name));
    expect(wrong.map((p) => p.name).slice(0, 5)).toEqual([]);
  });
});

describe("real Go advisories", () => {
  const entryFor = (file: string, name: string): KvEntry => {
    const rows = distillFor(record(file), ["go"]).filter((r) => r.packageName === name);
    return buildKvEntry(rows, "2026-11-09T00:00:00Z") as KvEntry;
  };
  const outcome = (entry: KvEntry, version: string) => summarizeVerdict(evaluate("go", entry, version)).outcome;

  describe("MAL-2025-2544 (github.com/belatedplanet/hypert), malware in every version", () => {
    const mal = record("go-MAL-2025-2544.json");
    it("is malware, found by its own id", () => {
      expect(classify(mal)).toBe("malware");
      expect(distillFor(mal, ["go"]).map((r) => r.packageName)).toEqual(["github.com/belatedplanet/hypert"]);
    });
    it("is stopped through the path the filter takes, at any version, including a pseudo-version", () => {
      const entry = entryFor("go-MAL-2025-2544.json", "github.com/belatedplanet/hypert");
      for (const file of ["v1.0.0.zip", "v0.0.0-20250101000000-0123456789ab.zip", "v2.0.0+incompatible.zip"]) {
        const [found] = parse(proxy("github.com/belatedplanet/hypert", file));
        expect(outcome(entry, found!.version), file).toBe("blocked");
      }
    });
  });

  describe("GHSA-69fq-xp46-6x23, found as malware by its CWE and naming three packages", () => {
    it("is malware by the rule, not by an id", () => {
      expect(classify(record("go-GHSA-69fq-xp46-6x23.json"))).toBe("malware");
    });
    it("keeps the one module a proxy can serve, and drops the two GitHub Actions", () => {
      const rows = distillFor(record("go-GHSA-69fq-xp46-6x23.json"), ["go"]);
      expect(rows.map((r) => r.packageName)).toEqual(["github.com/aquasecurity/trivy"]);
      expect(outcome(entryFor("go-GHSA-69fq-xp46-6x23.json", "github.com/aquasecurity/trivy"), "v0.69.4")).toBe("blocked");
      expect(outcome(entryFor("go-GHSA-69fq-xp46-6x23.json", "github.com/aquasecurity/trivy"), "v0.69.5")).toBe("allowed");
    });
  });

  describe("GO-2021-0076 (github.com/evanphx/json-patch), whose boundaries carry +incompatible", () => {
    const [row] = distillFor(record("go-GO-2021-0076.json"), ["go"]);
    const affected = (v: string) => isVersionAffected("go", row!.spec, v);
    it("matches inside both ranges and not at or past either fixed version", () => {
      expect(["v0.1.0", "v0.5.1", "v3.0.0+incompatible", "v3.0.0"].map(affected)).toEqual([true, true, true, true]);
      expect(["v0.5.2", "v3.0.1-0.20180525145409-4c9aadca8f89+incompatible", "v4.0.0+incompatible"].map(affected)).toEqual([false, false, false]);
    });
    it("was inert under the SemVer comparator for its shorthand-free boundaries only if they carried a build, which they do", async () => {
      const { compareSemver } = await import("../src/index.js");
      expect(compareSemver("3.0.0+incompatible", "3.0.0")).toBe(0);
    });
  });

  describe("GO-2020-0004, bounded by pseudo-versions", () => {
    const [row] = distillFor(record("go-GO-2020-0004.json"), ["go"]);
    const affected = (v: string) => isVersionAffected("go", row!.spec, v);
    it("orders them as the prerelease they are", () => {
      expect(["v0.0.0-20160722212129-ac0cc4484ad4", "v0.0.0-20180101000000-aaaaaaaaaaaa"].map(affected)).toEqual([true, true]);
      expect(["v0.0.0-20160722212128-ffffffffffff", "v0.0.0-20200131131040-063a3fb69896", "v1.0.0"].map(affected)).toEqual([false, false, false]);
    });
  });

  describe("GO-2021-0237 (github.com/AndrewBurian/powermux), a module with capitals", () => {
    it("is found by the exact path, from the URL the proxy writes with `!`", () => {
      const [found] = parse(proxy("github.com/!andrew!burian/powermux", "v1.1.0.zip"));
      expect(found!.name).toBe("github.com/AndrewBurian/powermux");
      const entry = entryFor("go-GO-2021-0237.json", "github.com/AndrewBurian/powermux");
      expect(kvKey("go", found!.name)).toBe("go:github.com/AndrewBurian/powermux");
      expect(outcome(entry, found!.version)).toBe("flagged");
      expect(outcome(entry, "v1.1.1")).toBe("allowed");
    });
    it("is not found by the lowercased path, which is a different module", () => {
      expect(kvKey("go", "github.com/andrewburian/powermux")).not.toBe(kvKey("go", "github.com/AndrewBurian/powermux"));
    });
  });
});

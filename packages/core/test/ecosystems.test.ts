import { describe, expect, it } from "vitest";
import {
  ADVISORY_COLUMNS,
  ECOSYSTEMS,
  ECOSYSTEM_IDS,
  ECOSYSTEM_LABELS,
  ENABLED_ECOSYSTEMS,
  advisoryFromRow,
  advisoryRow,
  compareVersions,
  distill,
  distillFor,
  ecosystemFromOsvName,
  ecosystemLabel,
  enabledEcosystemSqlList,
  isEcosystem,
  isEnabledEcosystem,
  kvKey,
  normalizeName,
  osvQueryBody,
  overrideKey,
  parsePackageCandidates,
  parsePackageUrl,
  toPurl,
  type Ecosystem,
  type OsvRecord,
  type ParsedPackage,
} from "../src/index.js";

/**
 * What every ecosystem must supply. This is a full Record over the ids, so adding an id without adding its
 * fixtures here does not compile; the tests below then hold each ecosystem to the same contract, so a call site
 * that was not wired up fails here rather than in production.
 */
interface Fixture {
  /** Real download URLs and what each must parse to. More than one when the registry serves more than one shape. */
  downloads: Array<{ url: string; pkg: ParsedPackage }>;
  /** URLs of this registry that are not package downloads. */
  notDownloads: string[];
  /** [raw, normalised] pairs: spellings of one name must collapse to the same string. */
  names: Array<[string, string]>;
  /** Strictly ascending. */
  ordered: string[];
  unparseableVersion: string;
  osv: { record: OsvRecord; name: string; namespace: string | null };
  overrideAccepts: string[];
  overrideRejects: string[];
}

const record = (osvName: string, name: string): OsvRecord => ({
  id: "MAL-2026-0001",
  modified: "2026-01-01T00:00:00Z",
  affected: [{ package: { ecosystem: osvName, name }, versions: ["1.0.0"] }],
});

const FIXTURES: Record<Ecosystem, Fixture> = {
  npm: {
    downloads: [
      { url: "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz", pkg: { ecosystem: "npm", namespace: "@babel", name: "core", version: "7.24.0" } },
    ],
    notDownloads: ["https://registry.npmjs.org/@babel/core", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.zip"],
    names: [["@Babel/Core", "@babel/core"], ["  LODASH ", "lodash"], ["event-stream", "event-stream"]],
    ordered: ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"],
    unparseableVersion: "not-a-version",
    osv: { record: record("npm", "@Scope/Evil"), name: "@scope/evil", namespace: "@scope" },
    overrideAccepts: ["lodash", "@scope/pkg", "event-stream", "a.b_c~d"],
    overrideRejects: ["", "..", "/x", "a//b", "a b", "@/x", "@scope/", "-x", "@scope/..", "Upper"],
  },
  pypi: {
    downloads: [
      { url: "https://files.pythonhosted.org/packages/ab/cd/ef/Flask_Cors-4.0.0-py2.py3-none-any.whl", pkg: { ecosystem: "pypi", namespace: null, name: "Flask_Cors", version: "4.0.0" } },
    ],
    notDownloads: ["https://pypi.org/simple/flask-cors/", "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.tar.gz.asc"],
    names: [["Foo.Bar__baz-Qux", "foo-bar-baz-qux"], ["Flask_Cors", "flask-cors"], ["requests", "requests"]],
    ordered: ["1.0.dev1", "1.0a1", "1.0rc1", "1.0", "1.0.post1", "1.1", "1!0.1"],
    unparseableVersion: "not-a-version",
    osv: { record: record("PyPI", "Flask_Cors"), name: "flask-cors", namespace: null },
    overrideAccepts: ["requests", "flask-cors", "a1"],
    overrideRejects: ["", "..", "a/b", "a b", "foo_bar", "foo.bar", "UPPER"],
  },
  cargo: {
    downloads: [
      // What the cargo client requests, and the shape that redirects to: measured behind Gateway.
      { url: "https://static.crates.io/crates/serde_json/1.0.100/download", pkg: { ecosystem: "cargo", namespace: null, name: "serde_json", version: "1.0.100" } },
      { url: "https://static.crates.io/crates/serde_json/serde_json-1.0.100.crate", pkg: { ecosystem: "cargo", namespace: null, name: "serde_json", version: "1.0.100" } },
    ],
    notDownloads: ["https://index.crates.io/config.json", "https://index.crates.io/se/rd/serde_json", "https://static.crates.io/crates/serde_json", "https://crates.io/crates/serde_json"],
    names: [["Serde_Json", "serde-json"], ["  TOKIO ", "tokio"], ["serde-json", "serde-json"]],
    ordered: ["0.0.0-0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"],
    unparseableVersion: "0.65",
    osv: { record: record("crates.io", "Serde_Json"), name: "serde-json", namespace: null },
    overrideAccepts: ["serde-json", "tokio", "a1"],
    overrideRejects: ["", "..", "a/b", "a b", "-x", "Upper", "a_b", "a.b"],
  },
  rubygems: {
    downloads: [
      { url: "https://rubygems.org/gems/rake-13.0.6.gem", pkg: { ecosystem: "rubygems", namespace: null, name: "rake", version: "13.0.6" } },
      // A platform build: the platform is dropped and the reading is unambiguous.
      { url: "https://rubygems.org/gems/nokogiri-1.16.2-x86_64-linux.gem", pkg: { ecosystem: "rubygems", namespace: null, name: "nokogiri", version: "1.16.2" } },
    ],
    notDownloads: ["https://rubygems.org/gems/rake", "https://rubygems.org/specs.4.8.gz", "https://rubygems.org/quick/Marshal.4.8/rake-13.0.6.gemspec.rz", "https://index.rubygems.org/versions"],
    // `_` is kept: a gem named with one is not the gem named with a hyphen.
    names: [["Rack", "rack"], ["  RAILS ", "rails"], ["3scale-time_range", "3scale-time_range"], ["3scale-time-range", "3scale-time-range"]],
    ordered: ["1.0.0.a", "1.0.0.pre", "1.0.0.rc1", "1.0.0.rc2", "1.0.0", "1.0.1", "1.10.0", "2.0.0"],
    unparseableVersion: "not-a-version",
    osv: { record: record("RubyGems", "Rack_Test"), name: "rack_test", namespace: null },
    overrideAccepts: ["rails", "rack-test", "a.b_c", "3scale-time_range"],
    overrideRejects: ["", "..", "/x", "a b", "-x", "_x", "Upper", "a/b"],
  },
};

const rowFor = (advisory: ReturnType<typeof distill>[number]): Record<string, unknown> =>
  Object.fromEntries(ADVISORY_COLUMNS.map((column, i) => [column, advisoryRow(advisory)[i]]));

describe("the registry's data", () => {
  it("lists each id once, in a shape that is safe to write into SQL and KV keys", () => {
    expect(new Set(ECOSYSTEM_IDS).size).toBe(ECOSYSTEM_IDS.length);
    for (const id of ECOSYSTEM_IDS) expect(id, id).toMatch(/^[a-z][a-z0-9-]*$/);
  });

  it("enables only ids it defines, and none twice", () => {
    expect(new Set(ENABLED_ECOSYSTEMS).size).toBe(ENABLED_ECOSYSTEMS.length);
    for (const id of ENABLED_ECOSYSTEMS) expect(ECOSYSTEM_IDS).toContain(id);
    expect(ENABLED_ECOSYSTEMS.length).toBeGreaterThan(0);
  });

  it("has a spec, a label and a unique Gateway name for every id", () => {
    expect(Object.keys(ECOSYSTEMS).sort()).toEqual([...ECOSYSTEM_IDS].sort());
    expect(Object.keys(ECOSYSTEM_LABELS).sort()).toEqual([...ECOSYSTEM_IDS].sort());
    const gateway = new Set<string>();
    const osv = new Set<string>();
    for (const id of ECOSYSTEM_IDS) {
      const spec = ECOSYSTEMS[id];
      expect(spec.id).toBe(id);
      expect(ecosystemLabel(id)).not.toBe("");
      expect(spec.gatewayName).toMatch(/^[a-z]+$/);
      expect(spec.purlType).toMatch(/^[a-z]+$/);
      gateway.add(spec.gatewayName);
      osv.add(spec.osvName);
    }
    expect(gateway.size).toBe(ECOSYSTEM_IDS.length);
    expect(osv.size).toBe(ECOSYSTEM_IDS.length);
  });

  it("uses the Gateway strings that were measured, not guessed", () => {
    // Gateway's API refuses an unknown pkg.ecosystem, so these were learned by asking it. RubyGems is "gem", not
    // "rubygems", which it refuses. The ones still to come are "golang" for Go (not "go") and "nuget".
    expect(Object.fromEntries(ECOSYSTEM_IDS.map((id) => [id, ECOSYSTEMS[id].gatewayName]))).toEqual({ npm: "npm", pypi: "pypi", cargo: "cargo", rubygems: "gem" });
  });

  it("recognises ids and enabled ids, and nothing else", () => {
    for (const id of ECOSYSTEM_IDS) expect(isEcosystem(id)).toBe(true);
    for (const id of ENABLED_ECOSYSTEMS) expect(isEnabledEcosystem(id)).toBe(true);
    for (const bad of ["", "NPM", "PyPI", "constructor", "__proto__", "toString", null, undefined, 3, {}]) {
      expect(isEcosystem(bad), String(bad)).toBe(false);
      expect(isEnabledEcosystem(bad), String(bad)).toBe(false);
    }
  });

  it("writes the enabled ids as the SQL list the refresh used to hard-code", () => {
    expect(enabledEcosystemSqlList()).toBe(ENABLED_ECOSYSTEMS.map((id) => `'${id}'`).join(","));
    expect(enabledEcosystemSqlList()).toBe("'npm','pypi','cargo','rubygems'");
  });
});

describe.each(ECOSYSTEM_IDS)("ecosystem %s meets the whole contract", (id) => {
  const spec = ECOSYSTEMS[id];
  const f = FIXTURES[id];

  it("parses each shape of its download URL", () => {
    for (const { url, pkg } of f.downloads) expect(spec.parse(new URL(url)), url).toEqual([pkg]);
  });

  it.runIf(ENABLED_ECOSYSTEMS.includes(id))("is recognised by the filter's entry points while it is enabled", () => {
    for (const { url, pkg } of f.downloads) {
      expect(parsePackageCandidates(url), url).toEqual([pkg]);
      expect(parsePackageUrl(url), url).toEqual(pkg);
    }
  });

  it.skipIf(ENABLED_ECOSYSTEMS.includes(id))("is invisible to the filter's entry points until it is enabled", () => {
    for (const { url } of f.downloads) {
      expect(parsePackageCandidates(url), url).toEqual([]);
      expect(parsePackageUrl(url), url).toBeNull();
    }
  });

  it("ignores URLs that are not its downloads", () => {
    for (const url of f.notDownloads) expect(spec.parse(new URL(url)), url).toEqual([]);
  });

  it("writes a package URL of its own type", () => {
    for (const { pkg } of f.downloads) expect(toPurl(pkg)).toMatch(new RegExp(`^pkg:${spec.purlType}/`));
  });

  it("collapses spellings of one name, and keys on the result", () => {
    for (const [raw, normalised] of f.names) {
      expect(normalizeName(id, raw), raw).toBe(normalised);
      expect(kvKey(id, raw), raw).toBe(`${id}:${normalised}`);
      expect(overrideKey("block", id, raw), raw).toBe(`override:block:${id}:${normalised}`);
    }
  });

  it("orders its versions, and refuses to order one it cannot read", () => {
    const list = f.ordered;
    for (let i = 0; i < list.length; i++) {
      for (let j = 0; j < list.length; j++) {
        const want = i === j ? 0 : i < j ? -1 : 1;
        expect(compareVersions(id, list[i]!, list[j]!), `${list[i]} vs ${list[j]}`).toBe(want);
      }
    }
    expect(compareVersions(id, f.unparseableVersion, "1.0.0")).toBeNull();
    expect(compareVersions(id, "1.0.0", f.unparseableVersion)).toBeNull();
  });

  it("is found by OSV's name for it, and queried under that name", () => {
    expect(ecosystemFromOsvName(spec.osvName, ECOSYSTEM_IDS)).toBe(id);
    expect(ecosystemFromOsvName(spec.osvName)).toBe(ENABLED_ECOSYSTEMS.includes(id) ? id : null);
    expect(osvQueryBody(id, "x").package.ecosystem).toBe(spec.osvName);
  });

  it("distils an OSV record into a row that survives the database and comes back equal", () => {
    const rows = distillFor(f.osv.record, [id]);
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.ecosystem).toBe(id);
    expect(row.packageName).toBe(f.osv.name);
    expect(row.namespace).toBe(f.osv.namespace);
    expect(advisoryFromRow(rowFor(row))).toEqual(row);
  });

  it("accepts the names an administrator may type, and rejects the rest", () => {
    for (const name of f.overrideAccepts) expect(spec.overrideNamePattern.test(name), name).toBe(true);
    for (const name of f.overrideRejects) expect(spec.overrideNamePattern.test(name), JSON.stringify(name)).toBe(false);
    expect(spec.maxNameLength).toBeGreaterThan(0);
  });
});

describe("distilling for a chosen set of ecosystems", () => {
  const both = {
    id: "GHSA-both-0001",
    modified: "2026-01-01T00:00:00Z",
    affected: [
      { package: { ecosystem: "npm", name: "shared" }, versions: ["1.0.0"] },
      { package: { ecosystem: "PyPI", name: "shared" }, versions: ["1.0.0"] },
    ],
  } as unknown as OsvRecord;

  it("keeps only the ones asked for", () => {
    expect(distillFor(both, ["pypi"]).map((r) => r.ecosystem)).toEqual(["pypi"]);
    expect(distillFor(both, ["npm"]).map((r) => r.ecosystem)).toEqual(["npm"]);
    expect(distillFor(both, ["npm", "pypi"]).map((r) => r.ecosystem).sort()).toEqual(["npm", "pypi"]);
    expect(distillFor(both, [])).toEqual([]);
  });
  it("is what distill does for the enabled ecosystems", () => {
    expect(distill(both)).toEqual(distillFor(both, ENABLED_ECOSYSTEMS));
  });
  it("is safe to hand to map, which passes an index as a second argument", () => {
    // The reason `distill` takes one argument: live.ts passes it to flatMap.
    expect([both].flatMap(distill).map((r) => r.ecosystem).sort()).toEqual(["npm", "pypi"]);
  });
});

describe("ecosystem lookups by OSV name", () => {
  it("never match an inherited object key, and are exact about case", () => {
    for (const bad of ["constructor", "__proto__", "toString", "hasOwnProperty", "pypi", "NPM", "", "npm ", undefined, null, 3]) {
      expect(ecosystemFromOsvName(bad), String(bad)).toBeNull();
    }
  });

  it("let a record's inherited-key ecosystem name through to nothing, not to PyPI", () => {
    const hostile = { id: "X-1", modified: "2026-01-01T00:00:00Z", affected: [{ package: { ecosystem: "constructor", name: "x" }, versions: ["1"] }] } as OsvRecord;
    expect(distill(hostile)).toEqual([]);
  });
});

describe("no URL is read as two ecosystems", () => {
  const corpus = [
    ...ECOSYSTEM_IDS.flatMap((id) => FIXTURES[id].downloads.map((d) => d.url)),
    ...ECOSYSTEM_IDS.flatMap((id) => FIXTURES[id].notDownloads),
    "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
    "https://registry.npmjs.org/@babel%2fcore/-/core-7.24.0.tgz",
    "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0.tar.gz",
    "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0-py3-none-any.whl",
    "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.zip",
    "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.tar.xz",
    "https://mirror.example.com/artifactory/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz",
    "https://example.com/",
  ];

  it.each(corpus)("%s", (url) => {
    const readers = ECOSYSTEM_IDS.filter((id) => ECOSYSTEMS[id].parse(new URL(url)).length > 0);
    expect(readers.length, `${url} parsed by ${readers.join(", ")}`).toBeLessThanOrEqual(1);
  });

  // The Go proxy URL for a pseudo-version under a module path containing "/packages/" is read as a PyPI sdist
  // whose name is "v0.0.0-20210101000000". Go is not an ecosystem yet, so nothing is exposed today; the roadmap's Go
  // phase must anchor each parser on a shape no other accepts, at which point this starts to pass and must be a plain test.
  it.fails("known gap: a Go pseudo-version URL under /packages/ is read as PyPI", () => {
    const url = new URL("https://proxy.golang.org/github.com/foo/packages/bar/@v/v0.0.0-20210101000000-0123456789ab.zip");
    expect(ECOSYSTEMS.pypi.parse(url)).toEqual([]);
  });
});

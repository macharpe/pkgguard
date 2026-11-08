import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  advisoryRow,
  compareVersions,
  distill,
  isVersionAffected,
  kvKey,
  malwareMessage,
  normalizeName,
  overrideKey,
  overrideMessage,
  parsePackageUrl,
  toPurl,
  type Ecosystem,
  type OsvRecord,
} from "../src/index.js";

/**
 * A snapshot of what npm and PyPI handling does today, over a corpus that includes the adversarial inputs found in
 * review. It exists so a refactor that must not change behaviour can prove it: the file is compared byte for byte.
 *
 * It records current behaviour, including behaviour that is wrong (a hyphenated sdist version, for example). When a
 * later change fixes such a case on purpose, regenerate it with `UPDATE_GOLDEN=1 npx vitest run golden-behaviour`
 * and review the diff.
 */
const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN = join(HERE, "fixtures", "golden-behaviour.json");

const URLS = [
  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
  "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
  "https://registry.npmjs.org/@babel%2fcore/-/core-7.24.0.tgz",
  "https://registry.npmjs.org/@babel%2Fcore/-/core-7.24.0.tgz",
  "https://registry.npmjs.org/%40babel%2Fcore/-/core-7.24.0.tgz",
  "https://registry.npmjs.org/%40babel/core/-/core-7.24.0.tgz",
  "https://registry.npmjs.org/react/-/react-19.0.0-rc.1.tgz",
  "https://registry.npmjs.org/foo/-/foo-1.0.0-beta.2+build.5.tgz",
  "https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz",
  "https://registry.npmjs.org//vfat-tools/-/vfat-tools-0.0.1-security.tgz",
  "https://registry.npmjs.org/vfat-tools/%2d/vfat-tools-0.0.1-security.tgz",
  "https://registry.npmjs.org/vfat-tools/-/vfat-tools-0.0.1-security.tgz?x=1#frag",
  "https://registry.npmjs.org/x/../lodash/-/lodash-4.17.21.tgz",
  "https://registry.npmjs.org/x/%2e%2e/lodash/-/lodash-4.17.21.tgz",
  "https://registry.npmjs.org/%252e/-/x-1.0.0.tgz",
  "https://registry.npmjs.org/LODASH/-/lodash-4.17.21.tgz",
  "https://registry.npmjs.org/@scope/pkg/-/@scope/pkg-1.0.0.tgz",
  "https://registry.npmjs.org/@scope%2fpkg/-/@scope%2fpkg-1.0.0.tgz",
  "https://mirror.example.com/artifactory/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz",
  "https://mirror.example.com/@org-proxy/lodash/-/lodash-4.17.21.tgz",
  "https://registry.npmjs.org/lodash",
  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.zip",
  "https://registry.npmjs.org/lodash/-/other-4.17.21.tgz",
  "https://registry.npmjs.org/lodash/-/lodash-.tgz",
  "https://registry.npmjs.org/@/x/-/x-1.0.0.tgz",
  "https://registry.npmjs.org/%E0%A4%A/-/x-1.0.0.tgz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/requests-2.31.0-py3-none-any.whl",
  "https://files.pythonhosted.org/packages/ab/cd/ef/Flask_Cors-4.0.0-py2.py3-none-any.whl",
  "https://files.pythonhosted.org/packages/ab/cd/ef/typing_extensions-4.9.0-1-py3-none-any.whl",
  "https://files.pythonhosted.org/packages/ab/cd/ef/numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1!2.0-py3-none-any.whl",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0%2Blocal-py3-none-any.whl",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.zip",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.tar.bz2",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.tar.xz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.tar.gz#sha256=00",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0-py3-none-any.whl.metadata",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.tar.gz.asc",
  "https://files.pythonhosted.org/packages/ab/cd/ef/evilpkg-1.0.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef%2Fevilpkg-1.0.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef%2Fevilpkg%2F..%2Fevilpkg-1.0.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0-1.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-bar-1.0-1.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0-rc1.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0-evil.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-bar-1.0-py3-none-any.whl",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0.TAR.GZ",
  "https://files.pythonhosted.org/packages/ab/cd/ef/foo-1.0-py3-none-any.WHL",
  "https://files.pythonhosted.org/packages/ab/cd/ef/ZENNITTTS-0.1.0.tar.gz",
  "https://files.pythonhosted.org/packages/ab/cd/ef//zennittts-0.1.0.tar.gz",
  "https://mirror.example.com/simple/foo/foo-1.0.tar.gz",
  "https://mirror.example.com/root/pypi/+f/abc/def/foo-1.0.tar.gz",
  "https://proxy.golang.org/github.com/foo/packages/bar/@v/v0.0.0-20210101000000-0123456789ab.zip",
  "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.zip",
  "https://rubygems.org/gems/rake-13.0.6.gem",
  "https://static.crates.io/crates/serde/serde-1.0.200.crate",
  "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
  "https://example.com/",
  "not a url",
  "",
];

const NAMES = [
  "lodash", "Lodash", "  lodash  ", "@babel/core", "@Babel/Core", "@scope/pkg", "event-stream", "a", "JSONStream",
  "Flask_Cors", "Foo.Bar__baz-Qux", "foo--bar", "foo_bar", "foo.bar", "ZENNITTTS", "typing_extensions",
  "x".repeat(200), "x".repeat(507), "x".repeat(508), "é", "\u202egnp", "a/b", "..", "",
];

const VERSIONS = {
  npm: [
    "0.0.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "10.0.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1",
    "1.0.0-RC1", "1.0.0-rc1", "1.0.0+build", "v1.0.0", " 1.0.0 ", "01.0.0", "1.0", "1", "1.0.0.0", "1.x", "latest", "",
    "1.0.99999999999999999999", "99999999999999999999.0.0", "0.0.0-20210101000000-abcdef123456", "2.0.0+incompatible",
  ],
  pypi: [
    "0.1", "1.0", "1.0.0", "1.0.1", "1.1", "2.0", "10.0", "1.0a1", "1.0b2", "1.0rc1", "1.0.dev1", "1.0.post1", "1!1.0",
    "2!0.1", "1.0+local", "1.0+local.2", "v1.0", "1.0-1", "1.0_1", "1.0.0.0", "1.0.0.99999999999999999999",
    "99999999999999999999!1.0", " 1.0 ", "1.0.", "abc", "", "1.0A1", "1.0.RC1",
  ],
} satisfies Record<Ecosystem, string[]>;

const SPECS = [
  { r: [[{ introduced: "0" }]], v: ["1.0.0"] },
  { r: [[{ introduced: "0" }, { fixed: "1.0.1" }]], v: [] },
  { r: [[{ introduced: "1.0" }, { last_affected: "1.0.1" }]], v: [] },
  { r: [[{ introduced: "0" }, { fixed: "1.x" }]], v: [] },
  { r: [[{ introduced: "1.0.0" }, { fixed: "2.0.0" }], [{ introduced: "10.0.0" }]], v: ["0.0.1"] },
  { r: [], v: ["1.0.0", "1.0"] },
  { r: [], v: [], all: true },
  { r: [], v: [] },
] as const;

const recordsDir = join(HERE, "fixtures");
const RECORDS: OsvRecord[] = readdirSync(recordsDir)
  .filter((f) => /^(GHSA|MAL)-.*\.json$/.test(f))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(recordsDir, f), "utf8")) as OsvRecord);

function compute(): Record<string, unknown> {
  const out: Record<string, unknown> = {};

  out["parse"] = URLS.map((url) => {
    const pkg = parsePackageUrl(url);
    return { url, pkg, purl: pkg ? toPurl(pkg) : null };
  });

  const names: Record<string, unknown> = {};
  for (const eco of ["npm", "pypi"] as const) {
    names[eco] = NAMES.map((name) => ({
      name: name.length > 40 ? `${name.slice(0, 8)}…(${name.length})` : name,
      normalized: normalizeName(eco, name),
      key: kvKey(eco, name),
      block: overrideKey("block", eco, name),
      allow: overrideKey("allow", eco, name),
    }));
  }
  out["names"] = names;

  const compare: Record<string, unknown> = {};
  for (const eco of ["npm", "pypi"] as const) {
    const list = VERSIONS[eco];
    compare[eco] = list.map((a) => list.map((b) => ({ "-1": "<", "0": "=", "1": ">", null: "?" })[String(compareVersions(eco, a, b))]).join(""));
  }
  out["compare"] = compare;

  const match: Record<string, unknown> = {};
  for (const eco of ["npm", "pypi"] as const) {
    match[eco] = SPECS.map((spec) => VERSIONS[eco].map((v) => (isVersionAffected(eco, spec as never, v) ? "1" : "0")).join(""));
  }
  out["match"] = match;

  out["distill"] = RECORDS.map((record) => ({
    id: record.id,
    rows: distill(record),
    columns: distill(record).map(advisoryRow),
  }));

  out["messages"] = (["npm", "pypi"] as const).map((ecosystem) => ({
    malware: malwareMessage({ ecosystem, name: "left-pad", version: "1.3.0", user: "dev@example.com", blocked: true, reason: "osv-malware", osvIds: ["MAL-1", "GHSA-x"], reference: "PG-ABCDEF" }),
    observed: malwareMessage({ ecosystem, name: "left-pad", version: null, user: null, blocked: false, reason: "override", osvIds: [] }),
    override: overrideMessage({ action: "added", mode: "allow", ecosystem, name: "left-pad", versions: ["1.0.0"], note: "n", actor: "a@example.com" }),
  }));

  return out;
}

describe("npm and PyPI behaviour, pinned", () => {
  it("matches the recorded snapshot exactly", () => {
    const actual = JSON.stringify(compute(), null, 1) + "\n";
    if (process.env["UPDATE_GOLDEN"] === "1" || !existsSync(GOLDEN)) {
      writeFileSync(GOLDEN, actual);
      return;
    }
    expect(actual === readFileSync(GOLDEN, "utf8"), "behaviour differs from fixtures/golden-behaviour.json").toBe(true);
  });

  it("covers every input it claims to", () => {
    const snapshot = JSON.parse(readFileSync(GOLDEN, "utf8")) as Record<string, unknown[]>;
    expect(snapshot["parse"]).toHaveLength(URLS.length);
    expect(snapshot["distill"]).toHaveLength(RECORDS.length);
    expect(RECORDS.length).toBeGreaterThanOrEqual(7);
  });
});

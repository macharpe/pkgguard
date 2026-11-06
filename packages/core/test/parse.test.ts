import { describe, expect, it } from "vitest";
import { parseNpmUrl, parsePackageUrl, parsePypiUrl, toPurl } from "../src/parse/index.js";

const npm = (path: string, host = "registry.npmjs.org") => new URL(`https://${host}${path}`);
const pypi = (path: string) => new URL(`https://files.pythonhosted.org${path}`);

describe("parseNpmUrl", () => {
  it("parses the real URL seen in the Gateway probe", () => {
    expect(parsePackageUrl("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")).toEqual({
      ecosystem: "npm",
      namespace: null,
      name: "lodash",
      version: "4.17.21",
    });
  });
  it("parses scoped packages where the tarball basename drops the scope", () => {
    expect(parseNpmUrl(npm("/@babel/core/-/core-7.24.0.tgz"))).toEqual({
      ecosystem: "npm",
      namespace: "@babel",
      name: "core",
      version: "7.24.0",
    });
  });
  it("parses the percent-encoded scope form", () => {
    expect(parseNpmUrl(npm("/@babel%2fcore/-/core-7.24.0.tgz"))).toMatchObject({
      namespace: "@babel",
      name: "core",
      version: "7.24.0",
    });
  });
  it("keeps prerelease and build metadata in the version", () => {
    expect(parseNpmUrl(npm("/react/-/react-19.0.0-rc.1.tgz"))?.version).toBe("19.0.0-rc.1");
    expect(parseNpmUrl(npm("/foo/-/foo-1.0.0-beta.2+build.5.tgz"))?.version).toBe("1.0.0-beta.2+build.5");
  });
  it("handles names containing hyphens", () => {
    expect(parseNpmUrl(npm("/event-stream/-/event-stream-3.3.6.tgz"))).toMatchObject({
      name: "event-stream",
      version: "3.3.6",
    });
  });
  it("tolerates a mirror path prefix", () => {
    expect(parseNpmUrl(npm("/artifactory/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz", "mirror.example.com"))).toMatchObject({
      name: "lodash",
      version: "4.17.21",
    });
  });
  it.each([
    "/lodash",
    "/lodash/-/lodash-4.17.21.zip",
    "/lodash/-/other-4.17.21.tgz",
    "/lodash/-/lodash-.tgz",
    "/-/lodash-4.17.21.tgz",
    "/lodash/-/x/lodash-4.17.21.tgz",
    "/lodash/%E0%A4%A/-/lodash-1.0.0.tgz",
    "/",
  ])("returns null for %s", (path) => {
    expect(parseNpmUrl(npm(path))).toBeNull();
  });
});

describe("parsePypiUrl", () => {
  const h = "/packages/70/7a/be4bd8bcbb24ea475856dd68159d78b03b2bb53dae369f69c9606b8888f5";
  it("parses a pure-python wheel (the URL pip actually used)", () => {
    expect(parsePypiUrl(pypi(`${h}/itsdangerous-2.1.2-py3-none-any.whl`))).toEqual({
      ecosystem: "pypi",
      namespace: null,
      name: "itsdangerous",
      version: "2.1.2",
    });
  });
  it("parses wheels with platform tags and a build tag", () => {
    expect(parsePypiUrl(pypi(`${h}/numpy-1.26.4-cp311-cp311-macosx_11_0_arm64.whl`))).toMatchObject({
      name: "numpy",
      version: "1.26.4",
    });
    expect(parsePypiUrl(pypi(`${h}/pkg-1.0-1-py3-none-any.whl`))).toMatchObject({ name: "pkg", version: "1.0" });
  });
  it("keeps the epoch and local parts of a wheel version as written", () => {
    expect(parsePypiUrl(pypi(`${h}/foo-1!2.0-py3-none-any.whl`))?.version).toBe("1!2.0");
    expect(parsePypiUrl(pypi(`${h}/foo-1.0+ubuntu1-py3-none-any.whl`))?.version).toBe("1.0+ubuntu1");
  });
  it("parses sdists, including hyphenated names", () => {
    expect(parsePypiUrl(pypi(`${h}/requests-2.31.0.tar.gz`))).toMatchObject({ name: "requests", version: "2.31.0" });
    expect(parsePypiUrl(pypi(`${h}/python-dateutil-2.9.0.tar.gz`))).toMatchObject({
      name: "python-dateutil",
      version: "2.9.0",
    });
    expect(parsePypiUrl(pypi(`${h}/foo-1.0.zip`))).toMatchObject({ name: "foo", version: "1.0" });
  });
  it.each([
    "/simple/requests/",
    `${h}/requests-2.31.0-py3-none-any.whl.metadata`,
    `${h}/notapkg.txt`,
    `${h}/bad-name.tar.gz`,
    `${h}/a-b-c.whl`,
    "/packages/",
    "/",
  ])("returns null for %s", (path) => {
    expect(parsePypiUrl(pypi(path))).toBeNull();
  });
});

describe("parsePackageUrl", () => {
  it("never throws on garbage", () => {
    for (const input of ["", "not a url", "https://", "ftp://x/-/y.tgz", "https://x/%"]) {
      expect(() => parsePackageUrl(input)).not.toThrow();
    }
    expect(parsePackageUrl("not a url")).toBeNull();
  });
  it("returns null for non-package traffic", () => {
    expect(parsePackageUrl("https://example.com/index.html")).toBeNull();
  });
});

describe("toPurl", () => {
  it("builds npm purls, encoding the scope", () => {
    expect(toPurl({ ecosystem: "npm", namespace: null, name: "lodash", version: "4.17.21" })).toBe(
      "pkg:npm/lodash@4.17.21",
    );
    expect(toPurl({ ecosystem: "npm", namespace: "@babel", name: "core", version: "7.0.0" })).toBe(
      "pkg:npm/%40babel/core@7.0.0",
    );
  });
  it("normalizes PyPI names", () => {
    expect(toPurl({ ecosystem: "pypi", namespace: null, name: "Typing_Extensions", version: "4.0.0" })).toBe(
      "pkg:pypi/typing-extensions@4.0.0",
    );
  });
});

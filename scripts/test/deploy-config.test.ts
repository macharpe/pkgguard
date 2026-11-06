import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generate } from "../generate-deploy-config.js";
import { FIELD_NAMES, WORKERS, field, renderConfig, validate, type FieldName } from "../lib/deploy-config.js";

const GOOD = {
  ACCOUNT_ID: "a".repeat(32),
  KV_ID: "b".repeat(32),
  D1_ID: "12345678-1234-1234-1234-123456789abc",
  ADMIN_HOSTNAME: "pkgguard.corp.example.org",
  TEAM_DOMAIN: "acme.cloudflareaccess.com",
  ACCESS_AUD: "c".repeat(64),
} satisfies Record<FieldName, string>;

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const filterTemplate = (): string => readFileSync(join(REPO_ROOT, "workers/filter/wrangler.jsonc"), "utf8");
const adminTemplate = (): string => readFileSync(join(REPO_ROOT, "workers/admin/wrangler.jsonc"), "utf8");

describe("placeholders", () => {
  it("every placeholder is distinct, so substitution can never cross-contaminate", () => {
    const values = FIELD_NAMES.map((n) => field(n).placeholder);
    expect(new Set(values).size).toBe(values.length);
  });
  it("no placeholder is a substring of another, or the occurrence counts are wrong", () => {
    const all = FIELD_NAMES.map((n) => [n, field(n).placeholder] as const);
    for (const [a, pa] of all) for (const [b, pb] of all) if (a !== b) expect(pb.includes(pa), `${a} is inside ${b}`).toBe(false);
  });
  it("every placeholder is rejected as a real value", () => {
    for (const name of FIELD_NAMES) {
      expect(validate(name, field(name).placeholder), name).toMatch(/placeholder/);
    }
  });
  it("every good test value passes its own format check", () => {
    for (const name of FIELD_NAMES) expect(validate(name, GOOD[name]), name).toBeNull();
  });
  it.each([
    ["ACCOUNT_ID", "ABC"],
    ["ACCOUNT_ID", "A".repeat(32)],
    ["KV_ID", "g".repeat(32)],
    ["D1_ID", "not-a-uuid"],
    ["ADMIN_HOSTNAME", "no_dots"],
    ["ADMIN_HOSTNAME", 'evil.example.com"}'],
    ["TEAM_DOMAIN", "acme.example.com"],
    ["ACCESS_AUD", "c".repeat(63)],
    ["ACCESS_AUD", "c".repeat(65)],
  ] as Array<[FieldName, string]>)("rejects malformed %s %j", (name, value) => {
    expect(validate(name, value)).not.toBeNull();
  });
  it("rejects values that could break out of a JSON string", () => {
    for (const name of FIELD_NAMES) expect(validate(name, `${GOOD[name]}","x":"y`), name).not.toBeNull();
  });
});

describe("the committed filter template", () => {
  it("matches the expected placeholder counts — no template drift", () => {
    expect(() => renderConfig(filterTemplate(), WORKERS["filter"]!, GOOD)).not.toThrow();
  });
  it("contains no real-looking identifiers", () => {
    const template = filterTemplate();
    for (const hex of template.match(/\b[0-9a-f]{32}\b/g) ?? []) expect(hex).toMatch(/^0{31}[01]$/);
    for (const uuid of template.match(/\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b/g) ?? []) {
      expect(uuid).toBe("00000000-0000-0000-0000-000000000000");
    }
  });
  it("keeps workers_dev and preview_urls off", () => {
    expect(filterTemplate()).toMatch(/"workers_dev":\s*false/);
    expect(filterTemplate()).toMatch(/"preview_urls":\s*false/);
  });
  it("ships with enforcement off", () => {
    expect(filterTemplate()).toMatch(/"ENFORCE":\s*"false"/);
  });
});

describe("renderConfig", () => {
  const template = `{"a":"${field("ACCOUNT_ID").placeholder}","k":"${field("KV_ID").placeholder}"}`;
  const expected = { ACCOUNT_ID: 1, KV_ID: 1 };

  it("substitutes every placeholder and marks the file as generated", () => {
    const out = renderConfig(template, expected, GOOD);
    expect(out.startsWith("// GENERATED")).toBe(true);
    expect(out).toContain(GOOD.ACCOUNT_ID);
    expect(out).toContain(GOOD.KV_ID);
    for (const name of FIELD_NAMES) expect(out).not.toContain(field(name).placeholder);
  });
  it("throws Template drift when a placeholder appears too often", () => {
    expect(() => renderConfig(`${template}${field("ACCOUNT_ID").placeholder}`, expected, GOOD)).toThrow(/Template drift/);
  });
  it("throws Template drift when a placeholder is missing from the template", () => {
    expect(() => renderConfig('{"a":"x"}', expected, GOOD)).toThrow(/Template drift/);
  });
  it("throws Template drift on an unexpected extra placeholder", () => {
    expect(() => renderConfig(`${template}"${field("ACCESS_AUD").placeholder}"`, expected, GOOD)).toThrow(/ACCESS_AUD placeholder appears 1 time/);
  });
  it("fails when a value is missing, reporting every problem at once", () => {
    expect(() => renderConfig(template, expected, {})).toThrow(/PKGGUARD_ACCOUNT_ID is not set[\s\S]*PKGGUARD_KV_ID is not set/);
  });
  it("fails when handed a placeholder as the real value", () => {
    expect(() => renderConfig(template, expected, { ...GOOD, ACCOUNT_ID: field("ACCOUNT_ID").placeholder })).toThrow(
      /still holds the placeholder/,
    );
  });
});

describe("generate (filesystem)", () => {
  let root: string;
  const writeEnv = (lines: string[]): void => writeFileSync(join(root, ".deploy.env"), lines.join("\n") + "\n");
  const goodEnv = (): string[] => [
    `PKGGUARD_ACCOUNT_ID=${GOOD.ACCOUNT_ID}`,
    `PKGGUARD_KV_ID=${GOOD.KV_ID}`,
    `PKGGUARD_D1_ID=${GOOD.D1_ID}`,
  ];

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "pkgguard-gen-"));
    mkdirSync(join(root, "workers/filter"), { recursive: true });
    writeFileSync(join(root, "workers/filter/wrangler.jsonc"), filterTemplate());
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("writes wrangler.local.jsonc at mode 0600 with real values and leaves no temp file", () => {
    writeEnv(goodEnv());
    const target = generate("filter", root);
    const text = readFileSync(target, "utf8");
    expect(text).toContain(GOOD.ACCOUNT_ID);
    expect(text).toContain(GOOD.D1_ID);
    expect(text).toContain('"name": "pkgguard-filter"');
    expect(statSync(target).mode & 0o777).toBe(0o600);
    expect(readdirSync(join(root, "workers/filter")).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });
  it("fails closed with no .deploy.env and writes nothing", () => {
    const saved = Object.fromEntries(Object.keys(process.env).filter((k) => k.startsWith("PKGGUARD_")).map((k) => [k, process.env[k]]));
    for (const k of Object.keys(saved)) delete process.env[k];
    try {
      expect(() => generate("filter", root)).toThrow(/\.deploy\.env\.example/);
      expect(existsSync(join(root, "workers/filter/wrangler.local.jsonc"))).toBe(false);
    } finally {
      Object.assign(process.env, saved);
    }
  });
  it("a failed run leaves the previous generated file untouched", () => {
    writeEnv(goodEnv());
    const target = generate("filter", root);
    const before = readFileSync(target, "utf8");
    writeEnv([`PKGGUARD_ACCOUNT_ID=${field("ACCOUNT_ID").placeholder}`, ...goodEnv().slice(1)]);
    expect(() => generate("filter", root)).toThrow(/placeholder/);
    expect(readFileSync(target, "utf8")).toBe(before);
  });
  it("environment variables win over the file", () => {
    writeEnv(goodEnv());
    process.env["PKGGUARD_ACCOUNT_ID"] = "d".repeat(32);
    try {
      expect(readFileSync(generate("filter", root), "utf8")).toContain("d".repeat(32));
    } finally {
      delete process.env["PKGGUARD_ACCOUNT_ID"];
    }
  });
  it("rejects an unknown worker", () => {
    expect(() => generate("nope", root)).toThrow(/Unknown worker/);
  });
});

describe("the committed admin template", () => {
  it("renders cleanly with every placeholder replaced", () => {
    const out = renderConfig(adminTemplate(), WORKERS["admin"]!, GOOD);
    for (const name of FIELD_NAMES) expect(out, name).not.toContain(field(name).placeholder);
    expect(out).toContain(GOOD.ADMIN_HOSTNAME);
    expect(out).toContain(GOOD.ACCESS_AUD);
  });
  it("puts the hostname in both the route and the public URL used in alerts", () => {
    const out = renderConfig(adminTemplate(), WORKERS["admin"]!, GOOD);
    expect(out).toContain(`"pattern": "${GOOD.ADMIN_HOSTNAME}"`);
    expect(out).toContain(`"PUBLIC_URL": "https://${GOOD.ADMIN_HOSTNAME}"`);
  });
  it("never ships workers.dev or preview URLs", () => {
    expect(adminTemplate()).toMatch(/"workers_dev":\s*false/);
    expect(adminTemplate()).toMatch(/"preview_urls":\s*false/);
  });
  it("detects drift in the hostname count", () => {
    expect(() => renderConfig(`${adminTemplate()}"${field("ADMIN_HOSTNAME").placeholder}"`, WORKERS["admin"]!, GOOD)).toThrow(/Template drift/);
  });
  it("does not declare the webhook: a secret must never sit in a committed config", () => {
    expect(adminTemplate()).not.toMatch(/GCHAT|webhook|chat\.googleapis/i);
    expect(filterTemplate()).not.toMatch(/GCHAT|webhook|chat\.googleapis/i);
  });
});

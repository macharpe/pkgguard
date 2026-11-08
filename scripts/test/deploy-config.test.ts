import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { generate } from "../generate-deploy-config.js";
import { ENFORCE_ENV, FIELD_NAMES, OBSERVE_ONLY_ENV, WORKERS, applyEnforce, applyObserveOnly, enforcementOf, field, observeOnlyOf, renderConfig, validate, type FieldName } from "../lib/deploy-config.js";

const GOOD = {
  ACCOUNT_ID: "a".repeat(32),
  KV_ID: "b".repeat(32),
  D1_ID: "12345678-1234-1234-1234-123456789abc",
  ADMIN_HOSTNAME: "pkgguard.corp.example.org",
  TEAM_DOMAIN: "acme.cloudflareaccess.com",
  ACCESS_AUD: "c".repeat(64),
} satisfies Record<FieldName, string>;

// Set for the whole file, so it is part of the ambient environment the filesystem tests must clear and then restore.
const SENTINEL = "PKGGUARD_TEST_SENTINEL";
beforeAll(() => {
  process.env[SENTINEL] = "kept";
});
afterAll(() => {
  delete process.env[SENTINEL];
});

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

  // The generator reads process.env before the file, so a developer who has run `source .deploy.env` would otherwise
  // change what these tests assert. Every test starts from an environment with no PKGGUARD_* variables.
  let ambient: Record<string, string | undefined>;
  const pkgguardVars = (): string[] => Object.keys(process.env).filter((k) => k.startsWith("PKGGUARD_"));

  beforeEach(() => {
    ambient = Object.fromEntries(pkgguardVars().map((k) => [k, process.env[k]]));
    for (const k of pkgguardVars()) delete process.env[k];
    root = mkdtempSync(join(tmpdir(), "pkgguard-gen-"));
    mkdirSync(join(root, "workers/filter"), { recursive: true });
    writeFileSync(join(root, "workers/filter/wrangler.jsonc"), filterTemplate());
  });
  afterEach(() => {
    for (const k of pkgguardVars()) delete process.env[k];
    Object.assign(process.env, ambient);
    rmSync(root, { recursive: true, force: true });
  });

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
    expect(() => generate("filter", root)).toThrow(/\.deploy\.env\.example/);
    expect(existsSync(join(root, "workers/filter/wrangler.local.jsonc"))).toBe(false);
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

  describe("enforcement", () => {
    const enforce = (target: string): string => /"ENFORCE":\s*"([^"]*)"/.exec(readFileSync(target, "utf8"))?.[1] ?? "missing";
    afterEach(() => delete process.env[ENFORCE_ENV]);

    it("stays observe-only when nothing is set, so a fresh checkout never blocks", () => {
      writeEnv(goodEnv());
      expect(enforce(generate("filter", root))).toBe("false");
    });
    it("is switched on by .deploy.env, so every redeploy keeps it on", () => {
      writeEnv([...goodEnv(), `${ENFORCE_ENV}=true`]);
      expect(enforce(generate("filter", root))).toBe("true");
      expect(enforce(generate("filter", root))).toBe("true");
    });
    it("can be set explicitly to false", () => {
      writeEnv([...goodEnv(), `${ENFORCE_ENV}=false`]);
      expect(enforce(generate("filter", root))).toBe("false");
    });
    it("is read from the environment first, then the file", () => {
      writeEnv([...goodEnv(), `${ENFORCE_ENV}=false`]);
      process.env[ENFORCE_ENV] = "true";
      expect(enforce(generate("filter", root))).toBe("true");
    });
    it("treats an empty value as unset", () => {
      writeEnv([...goodEnv(), `${ENFORCE_ENV}=`]);
      expect(enforce(generate("filter", root))).toBe("false");
    });
    it.each(["yes", "True", "TRUE", "1", "on", " true", "true "])("refuses %j rather than quietly meaning off, and writes nothing new", (bad) => {
      writeEnv(goodEnv());
      const target = generate("filter", root);
      const before = readFileSync(target, "utf8");
      writeEnv([...goodEnv(), `${ENFORCE_ENV}="${bad}"`]);
      expect(() => generate("filter", root)).toThrow(/exactly "true" or "false"/);
      expect(readFileSync(target, "utf8")).toBe(before);
    });
    it("never touches the template file itself", () => {
      writeEnv([...goodEnv(), `${ENFORCE_ENV}=true`]);
      generate("filter", root);
      expect(readFileSync(join(root, "workers/filter/wrangler.jsonc"), "utf8")).toBe(filterTemplate());
    });
  });

  describe("observe-only ecosystems", () => {
    const observeOnly = (target: string): string => /"OBSERVE_ONLY":\s*"([^"]*)"/.exec(readFileSync(target, "utf8"))?.[1] ?? "missing";
    afterEach(() => delete process.env[OBSERVE_ONLY_ENV]);

    it("is empty when nothing is set, so no ecosystem is held back by surprise", () => {
      writeEnv(goodEnv());
      expect(observeOnly(generate("filter", root))).toBe("");
    });
    it("is written from .deploy.env, in order, without repeats", () => {
      writeEnv([...goodEnv(), `${OBSERVE_ONLY_ENV}=pypi, npm,pypi`]);
      expect(observeOnly(generate("filter", root))).toBe("pypi,npm");
    });
    it("is read from the environment first, then the file", () => {
      writeEnv([...goodEnv(), `${OBSERVE_ONLY_ENV}=npm`]);
      process.env[OBSERVE_ONLY_ENV] = "pypi";
      expect(observeOnly(generate("filter", root))).toBe("pypi");
    });
    it("treats an empty value as none", () => {
      writeEnv([...goodEnv(), `${OBSERVE_ONLY_ENV}=`]);
      expect(observeOnly(generate("filter", root))).toBe("");
    });
    it.each(["pipy", "npm,pipy", "npm,", ",npm", "NPM", "all", "npm pypi", "*"])("refuses %j, because a typo must never mean blocking, and writes nothing new", (bad) => {
      writeEnv(goodEnv());
      const target = generate("filter", root);
      const before = readFileSync(target, "utf8");
      writeEnv([...goodEnv(), `${OBSERVE_ONLY_ENV}="${bad}"`]);
      expect(() => generate("filter", root)).toThrow(/comma-separated list of ecosystem ids/);
      expect(readFileSync(target, "utf8")).toBe(before);
    });
    it("is a filter setting only: the admin template has none, and the generator applies it to the filter alone", () => {
      expect(readFileSync(join(REPO_ROOT, "workers/admin/wrangler.jsonc"), "utf8")).not.toContain("OBSERVE_ONLY");
      expect(filterTemplate().match(/"OBSERVE_ONLY": ""/g)).toHaveLength(1);
    });
  });
});

describe("applyObserveOnly and observeOnlyOf", () => {
  const template = '{ "vars": { "OBSERVE_ONLY": "" } }';
  it("leaves the text alone when unset, empty or blank", () => {
    for (const value of [undefined, "", "   "]) expect(applyObserveOnly(template, value)).toBe(template);
  });
  it("replaces exactly the setting", () => {
    expect(applyObserveOnly(template, "pypi")).toBe('{ "vars": { "OBSERVE_ONLY": "pypi" } }');
    expect(applyObserveOnly(template, "npm,pypi")).toBe('{ "vars": { "OBSERVE_ONLY": "npm,pypi" } }');
  });
  it("fails on template drift: no setting, or two", () => {
    expect(() => applyObserveOnly("{}", "npm")).toThrow(/Template drift/);
    expect(() => applyObserveOnly(`${template}${template}`, "npm")).toThrow(/Template drift/);
  });
  it("names the valid ids when it refuses", () => {
    expect(() => applyObserveOnly(template, "pipy")).toThrow(/npm, pypi/);
  });
  it("reports what a generated config will keep observing", () => {
    expect(observeOnlyOf('"OBSERVE_ONLY": "npm, pypi"')).toEqual(["npm", "pypi"]);
    expect(observeOnlyOf('"OBSERVE_ONLY": ""')).toEqual([]);
    expect(observeOnlyOf("{}")).toEqual([]);
  });
});

describe("applyEnforce and enforcementOf", () => {
  const template = '{ "vars": { "ENFORCE": "false" } }';
  it("leaves the text alone when unset or empty", () => {
    expect(applyEnforce(template, undefined)).toBe(template);
    expect(applyEnforce(template, "")).toBe(template);
  });
  it("replaces exactly the setting", () => {
    expect(applyEnforce(template, "true")).toBe('{ "vars": { "ENFORCE": "true" } }');
    expect(applyEnforce(template, "false")).toBe(template);
  });
  it("fails on template drift: no setting, or two", () => {
    expect(() => applyEnforce("{}", "true")).toThrow(/Template drift/);
    expect(() => applyEnforce(`${template}${template}`, "true")).toThrow(/Template drift/);
  });
  it("reports what a generated config will do", () => {
    expect(enforcementOf('"ENFORCE": "true"')).toBe("ON");
    expect(enforcementOf('"ENFORCE": "false"')).toBe("off");
    expect(enforcementOf('"ENFORCE": "yes"')).toBe("off");
    expect(enforcementOf("{}")).toBe("unknown");
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

describe("generate (filesystem) environment isolation", () => {
  it("puts the ambient PKGGUARD_* variables back after the tests that clear them", () => {
    expect(process.env[SENTINEL]).toBe("kept");
  });
});

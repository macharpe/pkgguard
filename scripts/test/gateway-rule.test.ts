import { describe, expect, it } from "vitest";
import { CloudflareApi } from "../lib/cloudflare-api.js";
import {
  DEFAULT_PRECEDENCE,
  MIN_PRECEDENCE,
  RULE_NAME,
  assertPrecedenceFree,
  buildPayload,
  diffRule,
  findWorkerId,
  identityExpression,
  parseScope,
  type GatewayRule,
} from "../lib/gateway-rule.js";
import { execute, loadConfig, type Config } from "../gateway-rule.js";

const WORKER_ID = "a".repeat(32);
const SCOPE = { emails: ["demo@example.com"], domains: [] as string[] };

describe("parseScope", () => {
  it("trims, lowercases, de-duplicates and sorts emails", () => {
    expect(parseScope(" B@x.com, a@x.com ,A@X.com")).toEqual({ emails: ["a@x.com", "b@x.com"], domains: [] });
  });
  it("reads @domain entries as everyone at that domain", () => {
    expect(parseScope("@Example.com")).toEqual({ emails: [], domains: ["example.com"] });
    expect(parseScope("@b.example.com, @a.example.com,@A.example.com")).toEqual({ emails: [], domains: ["a.example.com", "b.example.com"] });
  });
  it("mixes the two", () => {
    expect(parseScope("@example.com, ops@partner.example")).toEqual({ emails: ["ops@partner.example"], domains: ["example.com"] });
  });
  it("trims surrounding whitespace, newlines included, so none reaches the expression", () => {
    expect(parseScope("a@x.com\n")).toEqual({ emails: ["a@x.com"], domains: [] });
    expect(parseScope("@x.com\n")).toEqual({ emails: [], domains: ["x.com"] });
  });
  it("refuses an empty value, because the rule is never unscoped", () => {
    expect(() => parseScope("")).toThrow(/at least one/);
    expect(() => parseScope(" , ")).toThrow(/at least one/);
  });
  it.each([
    'a@x.com" "evil@y.com',
    "a@x.com}",
    "a b@x.com",
    "not-an-email",
    "a@x",
    '"a@x.com"',
    "a@x.com\nb@y.com",
    "{a@x.com",
    "@",
    "@com",
    "@*.example.com",
    "@.example.com",
    "@example.com.",
    "@exa..mple.com",
    "@-example.com",
    "@example-.com",
    "@exa mple.com",
    '@example.com"',
    "@example.com|evil.com",
    "@(a|b).com",
    "@example.com$",
    "@@example.com",
    "@a@example.com",
    "@exämple.com",
  ])("rejects %j so it cannot break out of the expression", (bad) => {
    expect(() => parseScope(bad)).toThrow(/invalid entry/);
  });
});

describe("identityExpression", () => {
  const emails = (...e: string[]) => ({ emails: e, domains: [] as string[] });
  const domains = (...d: string[]) => ({ emails: [] as string[], domains: d });
  const patternOf = (expression: string): RegExp => {
    const m = /matches "\(\?i\)([^"]+)"/.exec(expression);
    if (!m) throw new Error(`no pattern in ${expression}`);
    return new RegExp(m[1] as string, "i");
  };

  it("renders the Gateway set syntax for emails", () => {
    expect(identityExpression(emails("a@x.com", "b@x.com"))).toBe('identity.email in {"a@x.com" "b@x.com"}');
  });
  it("renders an anchored, case-insensitive match for a domain, with no backslash anywhere", () => {
    const e = identityExpression(domains("example.com"));
    expect(e).toBe('identity.email matches "(?i)^[^@]+@example[.]com$"');
    expect(e).not.toContain("\\");
  });
  it("joins several clauses with `or`, emails first", () => {
    expect(identityExpression({ emails: ["a@x.com"], domains: ["a.com", "b.com"] })).toBe(
      'identity.email in {"a@x.com"} or identity.email matches "(?i)^[^@]+@a[.]com$" or identity.email matches "(?i)^[^@]+@b[.]com$"',
    );
  });
  describe("what the domain pattern actually matches", () => {
    const re = patternOf(identityExpression(domains("example.com")));
    it.each(["alice@example.com", "bob@example.com", "Alice@Example.COM", "alice+npm@example.com", "first.last@example.com", "a_b-c@example.com"])("matches %s", (addr) =>
      expect(re.test(addr)).toBe(true),
    );
    it.each([
      "alice@evil.example.com",
      "alice@example.com.evil.com",
      "alice@example.co",
      "alice@xexample.com",
      "alice@examplexcom",
      "alice@example.com.",
      "alice@example.com\n",
      "a@b@example.com",
      "@example.com",
      "example.com",
      "",
      "alice@example.com@evil.com",
      "alice@gmail.com",
    ])("does not match %j", (addr) => expect(re.test(addr)).toBe(false));
    it("treats the dot literally, not as any character", () => {
      expect(re.test("alice@exampleXcom")).toBe(false);
    });
  });
  it("revalidates even when called directly", () => {
    expect(() => identityExpression(emails('a@x.com" "b'))).toThrow(/invalid email/);
    expect(() => identityExpression(domains('a.com" or true or "'))).toThrow(/invalid domain/);
    expect(() => identityExpression(domains("a.com|b.com"))).toThrow(/invalid domain/);
    expect(() => identityExpression(domains("Example.com"))).toThrow(/invalid domain/);
    expect(() => identityExpression({ emails: [], domains: [] })).toThrow(/at least one/);
  });
});

describe("buildPayload", () => {
  const payload = buildPayload({ workerId: WORKER_ID, scope: SCOPE, precedence: DEFAULT_PRECEDENCE, enabled: false });
  it("is the shape the §9.1 probe proved the API accepts", () => {
    expect(payload).toMatchObject({
      name: RULE_NAME,
      action: "forward",
      filters: ["http"],
      traffic: 'pkg.ecosystem in {"npm" "pypi"}',
      identity: 'identity.email in {"demo@example.com"}',
      rule_settings: { forward: { worker_id: WORKER_ID } },
      enabled: false,
    });
  });
  it("requires the 32-hex Worker ID, not the name", () => {
    for (const bad of ["pkgguard-filter", "A".repeat(32), "a".repeat(31), ""]) {
      expect(() => buildPayload({ workerId: bad, scope: SCOPE, precedence: 47000, enabled: false })).toThrow(/Worker ID/);
    }
  });
  it("keeps the static pkg.* policies winning", () => {
    expect(() => buildPayload({ workerId: WORKER_ID, scope: SCOPE, precedence: MIN_PRECEDENCE - 1, enabled: false })).toThrow(/precedence/);
    expect(() => buildPayload({ workerId: WORKER_ID, scope: SCOPE, precedence: Number.NaN, enabled: false })).toThrow(/precedence/);
    expect(() => buildPayload({ workerId: WORKER_ID, scope: SCOPE, precedence: 47000.5, enabled: false })).toThrow(/precedence/);
  });
});

describe("findWorkerId / assertPrecedenceFree / diffRule", () => {
  it("finds the Worker by name and says what to do when absent", () => {
    expect(findWorkerId([{ id: WORKER_ID, name: "pkgguard-filter" }, { id: "b".repeat(32), name: "other" }])).toBe(WORKER_ID);
    expect(() => findWorkerId([{ id: WORKER_ID, name: "other" }])).toThrow(/deploy:filter/);
    expect(() => findWorkerId([{ id: "short", name: "pkgguard-filter" }])).toThrow(/unexpected ID/);
  });
  const rule = (over: Partial<GatewayRule>): GatewayRule => ({
    ...buildPayload({ workerId: WORKER_ID, scope: SCOPE, precedence: 47000, enabled: false }),
    id: "r1",
    ...over,
  });
  it("refuses a precedence held by someone else but not by our own rule", () => {
    expect(() => assertPrecedenceFree([rule({ name: "other", precedence: 47000 })], 47000)).toThrow(/already used/);
    expect(() => assertPrecedenceFree([rule({})], 47000)).not.toThrow();
  });
  it("reports drift field by field", () => {
    const desired = buildPayload({ workerId: WORKER_ID, scope: SCOPE, precedence: 47000, enabled: false });
    expect(diffRule(desired, rule({}))).toEqual([]);
    const drift = diffRule(desired, rule({ precedence: 47100, rule_settings: { forward: { worker_id: "c".repeat(32) } } }));
    expect(drift.map((d) => d.field)).toEqual(["precedence", "worker_id"]);
  });
});

interface Call {
  method: string;
  path: string;
  body?: unknown;
}

function fakeApi(opts: { rules?: GatewayRule[]; workers?: Array<{ id: string; name: string }> }) {
  const calls: Call[] = [];
  const api = {
    async call<T>(method: string, path: string, body?: unknown): Promise<T> {
      calls.push({ method, path, ...(body === undefined ? {} : { body }) });
      if (method === "GET" && path === "/gateway/rules") return (opts.rules ?? []) as T;
      if (method === "GET" && path === "/workers/workers") return (opts.workers ?? [{ id: WORKER_ID, name: "pkgguard-filter" }]) as T;
      if (method === "POST") return { id: "new-id" } as T;
      return {} as T;
    },
  };
  const writes = (): Call[] => calls.filter((c) => c.method !== "GET");
  return { api, calls, writes };
}

const config: Config = { scope: SCOPE, precedence: 47000 };
const live = (over: Partial<GatewayRule> = {}): GatewayRule => ({
  ...buildPayload({ workerId: WORKER_ID, scope: SCOPE, precedence: 47000, enabled: false }),
  id: "live-id",
  ...over,
});

async function run(command: Parameters<typeof execute>[0], opts: Parameters<typeof fakeApi>[0] = {}) {
  const fake = fakeApi(opts);
  const lines: string[] = [];
  let error: Error | undefined;
  try {
    await execute(command, fake.api, config, (l) => lines.push(l));
  } catch (e) {
    error = e as Error;
  }
  return { ...fake, lines, error };
}

describe("execute", () => {
  it("create posts one disabled rule", async () => {
    const r = await run("create");
    expect(r.error).toBeUndefined();
    expect(r.writes()).toHaveLength(1);
    expect(r.writes()[0]).toMatchObject({ method: "POST", path: "/gateway/rules", body: { enabled: false, action: "forward" } });
  });
  it("create refuses when the rule exists, and writes nothing", async () => {
    const r = await run("create", { rules: [live()] });
    expect(r.error?.message).toMatch(/already exists/);
    expect(r.writes()).toEqual([]);
  });
  it("create refuses a taken precedence, and writes nothing", async () => {
    const r = await run("create", { rules: [live({ name: "other", precedence: 47000 })] });
    expect(r.error?.message).toMatch(/already used/);
    expect(r.writes()).toEqual([]);
  });
  it("create without a deployed Worker writes nothing", async () => {
    const r = await run("create", { workers: [] });
    expect(r.error?.message).toMatch(/not found/);
    expect(r.writes()).toEqual([]);
  });
  it("enable PUTs the full desired rule with enabled=true", async () => {
    const r = await run("enable", { rules: [live()] });
    expect(r.writes()).toEqual([expect.objectContaining({ method: "PUT", path: "/gateway/rules/live-id", body: expect.objectContaining({ enabled: true, action: "forward" }) })]);
  });
  it("enable on a missing rule or missing Worker writes nothing", async () => {
    expect((await run("enable")).error?.message).toMatch(/run create first/);
    const noWorker = await run("enable", { rules: [live()], workers: [] });
    expect(noWorker.error?.message).toMatch(/not found/);
    expect(noWorker.writes()).toEqual([]);
  });
  it("enable is a no-op when already enabled and in sync", async () => {
    const r = await run("enable", { rules: [live({ enabled: true })] });
    expect(r.writes()).toEqual([]);
    expect(r.lines[0]).toMatch(/nothing to do/);
  });
  it("enable on an enabled but drifted rule reconciles it", async () => {
    const r = await run("enable", { rules: [live({ enabled: true, precedence: 47001 })] });
    expect(r.writes()).toHaveLength(1);
  });
  it("disable PUTs enabled=false", async () => {
    const r = await run("disable", { rules: [live({ enabled: true })] });
    expect(r.writes()[0]).toMatchObject({ method: "PUT", body: { enabled: false } });
  });
  describe("sync", () => {
    const stale = { traffic: 'pkg.ecosystem in {"npm"}' };

    it("writes the desired rule over a drifted one, naming every field it changes", async () => {
      const r = await run("sync", { rules: [live(stale)] });
      expect(r.error).toBeUndefined();
      expect(r.writes()).toEqual([expect.objectContaining({ method: "PUT", path: "/gateway/rules/live-id", body: expect.objectContaining({ traffic: 'pkg.ecosystem in {"npm" "pypi"}' }) })]);
      expect(r.lines.join("\n")).toMatch(/changing traffic: live "pkg\.ecosystem in \{\\"npm\\"\}" -> "pkg\.ecosystem in \{\\"npm\\" \\"pypi\\"\}"/);
      expect(r.lines.at(-1)).toMatch(/stays disabled/);
    });
    it.each([true, false])("never changes whether the rule is enabled (it was %s)", async (enabled) => {
      const r = await run("sync", { rules: [live({ ...stale, enabled })] });
      expect(r.writes()).toHaveLength(1);
      expect(r.writes()[0]).toMatchObject({ body: { enabled } });
      expect(r.lines.at(-1)).toMatch(enabled ? /stays ENABLED/ : /stays disabled/);
    });
    it("is a no-op, with no write, when already in sync", async () => {
      const r = await run("sync", { rules: [live({ enabled: true })] });
      expect(r.writes()).toEqual([]);
      expect(r.lines).toEqual(["already in sync; nothing to do"]);
    });
    it("fixes the scope as well as the traffic", async () => {
      const r = await run("sync", { rules: [live({ identity: 'identity.email in {"someone-else@example.com"}' })] });
      expect(r.writes()).toHaveLength(1);
      expect(r.lines.join("\n")).toMatch(/changing identity/);
    });
    it("refuses a missing rule, a missing Worker and a taken precedence, and writes nothing", async () => {
      const missing = await run("sync");
      expect(missing.error?.message).toMatch(/run create first/);
      const noWorker = await run("sync", { rules: [live(stale)], workers: [] });
      expect(noWorker.error?.message).toMatch(/not found/);
      const taken = await run("sync", { rules: [live(stale), live({ id: "other-id", name: "other", precedence: 47000 })] });
      expect(taken.error?.message).toMatch(/already used/);
      for (const r of [missing, noWorker, taken]) expect(r.writes()).toEqual([]);
    });
  });
  it("delete removes the rule, and is a no-op when absent", async () => {
    expect((await run("delete", { rules: [live()] })).writes()).toEqual([{ method: "DELETE", path: "/gateway/rules/live-id" }]);
    const absent = await run("delete");
    expect(absent.writes()).toEqual([]);
    expect(absent.lines[0]).toMatch(/nothing to delete/);
  });
  it("status never writes, and reports absent, in sync and drift", async () => {
    expect((await run("status")).lines[0]).toMatch(/^absent/);
    const ok = await run("status", { rules: [live()] });
    expect(ok.lines.join("\n")).toMatch(/in sync/);
    const drift = await run("status", { rules: [live({ enabled: true, precedence: 47100 })] });
    expect(drift.lines.join("\n")).toMatch(/ENABLED[\s\S]*drift in precedence/);
    for (const r of [ok, drift]) expect(r.writes()).toEqual([]);
  });
});

describe("loadConfig", () => {
  it("defaults the precedence and requires a scope", () => {
    expect(loadConfig({ PKGGUARD_SCOPE: "a@x.com" })).toEqual({ scope: { emails: ["a@x.com"], domains: [] }, precedence: DEFAULT_PRECEDENCE });
    expect(() => loadConfig({})).toThrow(/at least one/);
  });
  it("passes a custom precedence through for buildPayload to validate", () => {
    expect(loadConfig({ PKGGUARD_SCOPE: "a@x.com", PKGGUARD_FORWARD_PRECEDENCE: "48000" }).precedence).toBe(48000);
    expect(loadConfig({ PKGGUARD_SCOPE: "a@x.com", PKGGUARD_FORWARD_PRECEDENCE: "abc" }).precedence).toBeNaN();
  });
});

describe("CloudflareApi", () => {
  const SECRET = "tok_super_secret_value";
  const api = (response: Response) => new CloudflareApi("acct", SECRET, async () => response);
  it("returns the result of a successful call", async () => {
    const r = await api(Response.json({ success: true, result: [1, 2] })).call<number[]>("GET", "/x");
    expect(r).toEqual([1, 2]);
  });
  it("sends the bearer token and JSON body", async () => {
    let seen: { url: string; init: RequestInit } | undefined;
    const client = new CloudflareApi("acct", SECRET, async (url, init) => {
      seen = { url, init };
      return Response.json({ success: true, result: {} });
    });
    await client.call("POST", "/gateway/rules", { a: 1 });
    expect(seen?.url).toBe("https://api.cloudflare.com/client/v4/accounts/acct/gateway/rules");
    expect((seen?.init.headers as Record<string, string>)["authorization"]).toBe(`Bearer ${SECRET}`);
    expect(seen?.init.body).toBe('{"a":1}');
  });
  it.each([
    ["an API error", Response.json({ success: false, result: null, errors: [{ code: 1001, message: "bad rule" }] }, { status: 400 })],
    ["a non-JSON body", new Response("<html>", { status: 502 })],
    ["success:false on a 200", Response.json({ success: false, result: null, errors: [] })],
  ])("throws on %s and never includes the token", async (_n, response) => {
    const err = await api(response).call("GET", "/x").catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).not.toContain(SECRET);
  });
  it("includes the Cloudflare error code and message", async () => {
    const err = await api(Response.json({ success: false, result: null, errors: [{ code: 1001, message: "bad rule" }] }, { status: 400 }))
      .call("GET", "/x")
      .catch((e: Error) => e);
    expect((err as Error).message).toMatch(/400.*1001: bad rule/);
  });
});

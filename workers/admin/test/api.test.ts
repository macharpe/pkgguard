import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AUD_API, AUD_UI, NOW_MS } from "./jwt-helpers.js";
import { adminEnv, addAdvisory, addDetection, call, iso, putKv, serviceToken, setup, user } from "./harness.js";

beforeEach(setup);

const body = async (r: Response) => (await r.json()) as any;

describe("authentication", () => {
  it("401 with no assertion, on both the dashboard and the API", async () => {
    expect((await call("/", null)).status).toBe(401);
    expect((await call("/api/status", null)).status).toBe(401);
  });
  it("403 on garbage, with no detail about why", async () => {
    const r = await call("/api/status", "not.a.jwt");
    expect(r.status).toBe(403);
    expect(await body(r)).toEqual({ error: "invalid Access assertion" });
  });
  it("binds the audience to the path: a dashboard token is refused on /api and an API token on /", async () => {
    expect((await call("/api/status", await user(AUD_UI))).status).toBe(403);
    expect((await call("/", await user(AUD_API))).status).toBe(403);
    expect((await call("/api/status", await user(AUD_API))).status).toBe(200);
    expect((await call("/", await user(AUD_UI))).status).toBe(200);
  });
  it("treats /api itself as the API application", async () => {
    expect((await call("/api", await user(AUD_UI))).status).toBe(403);
  });
  it("is not fooled by path tricks that look like /api but are not", async () => {
    expect((await call("/apix", await user(AUD_UI))).status).toBe(404);
    expect((await call("/API/status", await user(AUD_UI))).status).toBe(404);
  });
  it("lets a service token reach /api/*", async () => {
    const r = await call("/api/whoami", await serviceToken());
    expect(await body(r)).toEqual({ actor: { kind: "service-token", clientId: "tok123.access" }, label: "service-token:tok123.access" });
  });
  it("reports a person's email on /api/whoami", async () => {
    expect((await body(await call("/api/whoami", await user(AUD_API, "a@b.co")))).actor).toEqual({ kind: "user", email: "a@b.co" });
  });
  it("authenticates before routing, so an unknown path never leaks existence to the unauthenticated", async () => {
    expect((await call("/api/nope", null)).status).toBe(401);
    expect((await call("/api/nope", await user(AUD_API))).status).toBe(404);
  });
  it("refuses writes for now with 405 once authenticated, and 401 before", async () => {
    expect((await call("/api/status", null, { method: "POST" })).status).toBe(401);
    expect((await call("/api/status", await user(AUD_API), { method: "POST" })).status).toBe(405);
    expect((await call("/api/status", await user(AUD_API), { method: "DELETE" })).status).toBe(405);
  });
});

describe("the dashboard page", () => {
  it("is HTML with hardening headers", async () => {
    const r = await call("/", await user(AUD_UI));
    expect(r.headers.get("content-type")).toMatch(/text\/html/);
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("cache-control")).toBe("no-store");
  });
});

describe("GET /api/status", () => {
  const status = async () => body(await call("/api/status", await user(AUD_API)));

  it("is well formed on an empty database", async () => {
    const s = await status();
    expect(s).toMatchObject({ ecosystems: [], advisories: {}, detections: { total: 0, last24h: { blocked: 0, flagged: 0, allowed: 0, error: 0 } }, lastRefresh: null });
    expect(s.generatedAt).toBe(new Date(NOW_MS).toISOString());
  });
  it("counts advisories per ecosystem and kind, excluding withdrawn ones", async () => {
    await addAdvisory({ ecosystem: "npm", id: "M1", name: "a", kind: "malware" });
    await addAdvisory({ ecosystem: "npm", id: "M2", name: "b", kind: "malware" });
    await addAdvisory({ ecosystem: "npm", id: "V1", name: "c", kind: "vulnerability" });
    await addAdvisory({ ecosystem: "pypi", id: "M3", name: "d", kind: "malware" });
    await addAdvisory({ ecosystem: "npm", id: "GONE", name: "e", kind: "malware", withdrawn: 1 });
    expect((await status()).advisories).toEqual({ npm: { malware: 2, vulnerability: 1 }, pypi: { malware: 1 } });
  });
  it("counts the last 24 hours separately from the total", async () => {
    await addDetection({ verdict: "blocked", ts: iso(-3600) });
    await addDetection({ verdict: "flagged", ts: iso(-7200) });
    await addDetection({ verdict: "flagged", ts: iso(-8000) });
    await addDetection({ verdict: "blocked", ts: iso(-25 * 3600) });
    const s = await status();
    expect(s.detections).toEqual({ total: 4, last24h: { blocked: 1, flagged: 2, allowed: 0, error: 0 } });
  });
  it("returns the sync state and the most recent refresh", async () => {
    await env.DB.prepare("INSERT INTO sync_state (ecosystem, last_modified, record_count, last_synced_at) VALUES ('npm','2026-11-05T00:00:00Z',123,'2026-11-05T01:00:00Z')").run();
    for (const [id, at] of [["old", "2026-11-01T00:00:00Z"], ["new", "2026-11-04T00:00:00Z"]] as const) {
      await env.DB.prepare("INSERT INTO refresh_runs (id, kind, trigger, status, started_at) VALUES (?, 'manual', 'cron', 'complete', ?)").bind(id, at).run();
    }
    const s = await status();
    expect(s.ecosystems).toEqual([{ ecosystem: "npm", last_modified: "2026-11-05T00:00:00Z", record_count: 123, last_synced_at: "2026-11-05T01:00:00Z" }]);
    expect(s.lastRefresh.id).toBe("new");
  });
  it("memoises the expensive advisory count but not the cheap detection count", async () => {
    await addAdvisory({ ecosystem: "npm", id: "M1", name: "a", kind: "malware" });
    expect((await status()).advisories.npm.malware).toBe(1);
    await addAdvisory({ ecosystem: "npm", id: "M2", name: "b", kind: "malware" });
    await addDetection({ verdict: "blocked" });
    const s = await status();
    expect(s.advisories.npm.malware).toBe(1);
    expect(s.detections.total).toBe(1);
  });
});

describe("GET /api/detections", () => {
  const get = async (qs = "") => body(await call(`/api/detections${qs}`, await user(AUD_API)));

  it("returns newest first", async () => {
    for (const n of ["a", "b", "c"]) await addDetection({ package_name: n });
    expect((await get()).items.map((i: any) => i.package_name)).toEqual(["c", "b", "a"]);
  });
  it("filters by verdict and ecosystem, and combines filters", async () => {
    await addDetection({ verdict: "blocked", ecosystem: "npm", package_name: "n1" });
    await addDetection({ verdict: "blocked", ecosystem: "pypi", package_name: "p1" });
    await addDetection({ verdict: "flagged", ecosystem: "npm", package_name: "n2" });
    expect((await get("?verdict=blocked")).items.map((i: any) => i.package_name)).toEqual(["p1", "n1"]);
    expect((await get("?ecosystem=npm")).items.map((i: any) => i.package_name)).toEqual(["n2", "n1"]);
    expect((await get("?verdict=blocked&ecosystem=npm")).items.map((i: any) => i.package_name)).toEqual(["n1"]);
  });
  it("paginates with a keyset cursor without gaps or repeats", async () => {
    for (let i = 1; i <= 7; i++) await addDetection({ package_name: `p${i}` });
    const first = await get("?limit=3");
    expect(first.items.map((i: any) => i.package_name)).toEqual(["p7", "p6", "p5"]);
    const second = await get(`?limit=3&before=${first.nextBefore}`);
    expect(second.items.map((i: any) => i.package_name)).toEqual(["p4", "p3", "p2"]);
    const third = await get(`?limit=3&before=${second.nextBefore}`);
    expect(third.items.map((i: any) => i.package_name)).toEqual(["p1"]);
    expect(third.nextBefore).toBeNull();
  });
  it("has no cursor when everything fits, including exactly one full page", async () => {
    for (let i = 0; i < 3; i++) await addDetection({});
    expect((await get("?limit=3")).nextBefore).toBeNull();
    expect((await get("?limit=2")).nextBefore).not.toBeNull();
  });
  it.each(["?verdict=evil", "?ecosystem=gem", "?limit=0", "?limit=201", "?limit=abc", "?limit=-1", "?limit=1.5", "?before=x", "?before=0"])(
    "rejects %s with 400",
    async (qs) => {
      expect((await call(`/api/detections${qs}`, await user(AUD_API))).status).toBe(400);
    },
  );
  it("treats SQL in a parameter as a plain invalid value", async () => {
    const r = await call(`/api/detections?verdict=${encodeURIComponent("blocked' OR '1'='1")}`, await user(AUD_API));
    expect(r.status).toBe(400);
  });
});

describe("GET /api/advisories", () => {
  const get = async (qs: string) => call(`/api/advisories${qs}`, await user(AUD_API));
  const kv = (m: unknown[], c: unknown[]) => ({ v: 1, m, c, u: iso() });

  it("requires q", async () => {
    expect((await get("")).status).toBe(400);
    expect((await get("?q=")).status).toBe(400);
    expect((await get("?q=%20%20")).status).toBe(400);
  });
  it("rejects overlong q and version, and an unknown ecosystem", async () => {
    expect((await get(`?q=${"a".repeat(215)}`)).status).toBe(400);
    expect((await get(`?q=a&version=${"1".repeat(129)}`)).status).toBe(400);
    expect((await get("?q=a&ecosystem=gem")).status).toBe(400);
  });
  it("matches by prefix and groups advisories by package, malware apart from vulnerabilities", async () => {
    await addAdvisory({ ecosystem: "npm", id: "M1", name: "lodash", kind: "malware" });
    await addAdvisory({ ecosystem: "npm", id: "V1", name: "lodash", kind: "vulnerability", severity: "HIGH" });
    await addAdvisory({ ecosystem: "npm", id: "V2", name: "lodash-es", kind: "vulnerability" });
    await addAdvisory({ ecosystem: "npm", id: "V3", name: "other", kind: "vulnerability" });
    const { items } = await body(await get("?q=lodash"));
    expect(items.map((i: any) => i.name)).toEqual(["lodash", "lodash-es"]);
    expect(items[0].malware.map((a: any) => a.osv_id)).toEqual(["M1"]);
    expect(items[0].vulnerabilities.map((a: any) => a.osv_id)).toEqual(["V1"]);
  });
  it("normalises the query per ecosystem: PEP 503 for PyPI, lowercase for npm", async () => {
    await addAdvisory({ ecosystem: "pypi", id: "P1", name: "typing-extensions", kind: "vulnerability" });
    await addAdvisory({ ecosystem: "npm", id: "N1", name: "jquery", kind: "vulnerability" });
    expect((await body(await get("?q=Typing_Extensions"))).items.map((i: any) => i.name)).toEqual(["typing-extensions"]);
    expect((await body(await get("?q=JQuery"))).items.map((i: any) => i.name)).toEqual(["jquery"]);
  });
  it("finds scoped npm packages", async () => {
    await addAdvisory({ ecosystem: "npm", id: "S1", name: "@solana/web3.js", kind: "malware" });
    expect((await body(await get("?q=@solana%2Fweb3"))).items.map((i: any) => i.name)).toEqual(["@solana/web3.js"]);
  });
  it("restricts to one ecosystem on request", async () => {
    await addAdvisory({ ecosystem: "npm", id: "N1", name: "requests", kind: "vulnerability" });
    await addAdvisory({ ecosystem: "pypi", id: "P1", name: "requests", kind: "vulnerability" });
    expect((await body(await get("?q=requests"))).items).toHaveLength(2);
    expect((await body(await get("?q=requests&ecosystem=pypi"))).items.map((i: any) => i.ecosystem)).toEqual(["pypi"]);
  });
  it("excludes withdrawn advisories", async () => {
    await addAdvisory({ ecosystem: "npm", id: "W1", name: "gone", kind: "malware", withdrawn: 1 });
    expect((await body(await get("?q=gone"))).items).toEqual([]);
  });
  it("treats LIKE wildcards and quotes literally", async () => {
    await addAdvisory({ ecosystem: "npm", id: "N1", name: "abc", kind: "vulnerability" });
    for (const q of ["%", "_", "a%", "'; DROP TABLE advisories;--", '" OR 1=1']) {
      expect((await body(await get(`?q=${encodeURIComponent(q)}`))).items, q).toEqual([]);
    }
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories").first<{ n: number }>())?.n).toBe(1);
  });
  it("caps the number of packages and says it truncated", async () => {
    for (let i = 0; i < 30; i++) await addAdvisory({ ecosystem: "npm", id: `V${i}`, name: `pkg-${String(i).padStart(2, "0")}`, kind: "vulnerability" });
    const r = await body(await get("?q=pkg-"));
    expect(r.items).toHaveLength(25);
    expect(r.truncated).toBe(true);
  });

  describe("simulated OSV verdict, from the same index the filter reads", () => {
    const range = (introduced: string, fixed: string) => ({ r: [[{ introduced }, { fixed }]], v: [] });
    beforeEach(async () => {
      await addAdvisory({ ecosystem: "npm", id: "CVE-1", name: "lodash", kind: "vulnerability" });
      await addAdvisory({ ecosystem: "npm", id: "MAL-1", name: "evil", kind: "malware" });
      await putKv("npm:lodash", kv([], [{ id: "CVE-1", sev: "HIGH", ...range("0", "4.17.21") }]));
      await putKv("npm:evil", kv([{ id: "MAL-1", all: true, r: [], v: [] }], []));
    });
    const outcome = async (qs: string) => (await body(await get(qs))).items[0]?.osv;

    it("flags a vulnerable version, allows the fixed one", async () => {
      expect(await outcome("?q=lodash&version=4.17.20")).toEqual({ version: "4.17.20", outcome: "flagged", reason: "osv-cve", osvIds: ["CVE-1"] });
      expect(await outcome("?q=lodash&version=4.17.21")).toEqual({ version: "4.17.21", outcome: "allowed", reason: null, osvIds: [] });
    });
    it("blocks malware", async () => {
      expect(await outcome("?q=evil&version=9.9.9")).toMatchObject({ outcome: "blocked", reason: "osv-malware", osvIds: ["MAL-1"] });
    });
    it("gives no verdict without a version", async () => {
      expect((await body(await get("?q=lodash"))).items[0].osv).toBeUndefined();
    });
    it("gives no verdict for a prefix-only match, only for the exact package", async () => {
      expect((await body(await get("?q=lodas&version=4.17.20"))).items[0].osv).toBeUndefined();
    });
    it("allows when the index has no entry or a negative-cache marker", async () => {
      await addAdvisory({ ecosystem: "npm", id: "CVE-2", name: "ghost", kind: "vulnerability" });
      expect(await outcome("?q=ghost&version=1.0.0")).toMatchObject({ outcome: "allowed" });
      await putKv("npm:ghost", { n: 1, u: iso() });
      expect(await outcome("?q=ghost&version=1.0.0")).toMatchObject({ outcome: "allowed" });
    });
    it("reports a lookup error, as the filter would, rather than crashing on a corrupt index entry", async () => {
      await env.PKG_INDEX.put("npm:lodash", "{not json");
      const r = await get("?q=lodash&version=4.17.20");
      expect(r.status).toBe(200);
      expect((await body(r)).items[0].osv).toEqual({ version: "4.17.20", outcome: "error", reason: "lookup-error", osvIds: [] });
    });
    it("treats a well-formed but wrong-shaped entry as no match instead of failing", async () => {
      await putKv("npm:lodash", { hello: "world" });
      expect(await outcome("?q=lodash&version=4.17.20")).toMatchObject({ outcome: "allowed" });
    });
    it("matches the PyPI exact name after normalisation", async () => {
      await addAdvisory({ ecosystem: "pypi", id: "PY-1", name: "typing-extensions", kind: "vulnerability" });
      await putKv("pypi:typing-extensions", kv([], [{ id: "PY-1", ...range("0", "4.0.0") }]));
      expect(await outcome("?q=Typing_Extensions&version=3.10.0")).toMatchObject({ outcome: "flagged", osvIds: ["PY-1"] });
    });
  });
});

describe("routing and failure handling", () => {
  it("404s an authenticated unknown path", async () => {
    expect((await call("/api/unknown", await user(AUD_API))).status).toBe(404);
    expect((await call("/favicon.ico", await user(AUD_UI))).status).toBe(404);
  });
  it("answers HEAD like GET", async () => {
    expect((await call("/api/status", await user(AUD_API), { method: "HEAD" })).status).toBe(200);
  });
  it("returns a generic 500 with an exact body, and never leaks the underlying error", async () => {
    const broken = adminEnv({ DB: { prepare: () => { throw new Error("secret table detail"); } } as never });
    const r = await call("/api/status", await user(AUD_API), {}, broken);
    expect(r.status).toBe(500);
    expect(await r.text()).toBe('{"error":"internal error"}');
  });
  it("logs the reason server-side without the stack", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const broken = adminEnv({ DB: { prepare: () => { throw new Error("db exploded"); } } as never });
    await call("/api/status", await user(AUD_API), {}, broken);
    expect(spy).toHaveBeenCalledWith("unhandled", "db exploded");
    spy.mockRestore();
  });
});

import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OsvRecord } from "@pkgguard/core";
import eventStreamJson from "../../../packages/core/test/fixtures/GHSA-mh6f-8j2x-4483.json";
import ctxJson from "../../../packages/core/test/fixtures/GHSA-4g82-3jcr-q52w.json";
import lodashJson from "../../../packages/core/test/fixtures/GHSA-35jh-r3h4-6jhm.json";
import { PYPI, detections, jsonResponse, reset, run, seed, tarball, NPM } from "./harness.js";

const eventStream = eventStreamJson as unknown as OsvRecord;
const ctxRecord = ctxJson as unknown as OsvRecord;
const lodashCve = lodashJson as unknown as OsvRecord;

const ENFORCING = { ENFORCE: "true" };

beforeEach(reset);
afterEach(() => vi.restoreAllMocks());

describe("traffic that is not a package download", () => {
  it("passes straight through and records nothing", async () => {
    const { response, next, upstream } = await run(`${NPM}/lodash`, { env: ENFORCING });
    expect(next).toHaveBeenCalledOnce();
    expect(response).toBe(upstream);
    expect(await detections()).toEqual([]);
  });
});

describe("index hits", () => {
  beforeEach(async () => {
    await seed(eventStream, "npm", "event-stream");
    await seed(lodashCve, "npm", "lodash");
    await seed(ctxRecord, "pypi", "ctx");
  });

  it("blocks malware with a 403 and never calls next (enforcing)", async () => {
    const { response, next } = await run(tarball("event-stream", "3.3.6"), { env: ENFORCING, headers: { accept: "text/html" } });
    expect(response.status).toBe(403);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(next).not.toHaveBeenCalled();
    const html = await response.text();
    expect(html).toContain("event-stream@3.3.6");
    expect(html).toContain("https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483");
    expect(await detections()).toEqual([
      expect.objectContaining({
        ecosystem: "npm",
        package_name: "event-stream",
        version: "3.3.6",
        purl: "pkg:npm/event-stream@3.3.6",
        verdict: "blocked",
        reason: "osv-malware",
        osv_ids: "GHSA-mh6f-8j2x-4483",
        user_email: "dev@example.com",
        src_ip: "203.0.113.9",
        source: "index",
      }),
    ]);
  });

  describe("the reference that ties a block together", () => {
    const REFERENCE = /^PG-[0-9A-HJKMNP-TV-Z]{6}$/;
    const NPM_CLIENT = { accept: "*/*", "user-agent": "npm/11.18.0 node/v24.18.0 darwin arm64" };
    const PIP_CLIENT = { accept: "*/*", "user-agent": "pip/26.2.2" };

    it("is the same code in the response header, the reason phrase, the body and the detection row", async () => {
      const { response } = await run(tarball("event-stream", "3.3.6"), { env: ENFORCING, headers: PIP_CLIENT });
      const reference = response.headers.get("x-pkgguard-reference") ?? "";
      expect(reference).toMatch(REFERENCE);
      expect(response.statusText).toContain(reference);
      expect(await response.text()).toContain(reference);
      expect((await detections())[0]?.reference).toBe(reference);
    });
    it("gives each block its own code", async () => {
      const seen = new Set<string>();
      for (let i = 0; i < 5; i++) seen.add((await run(tarball("event-stream", "3.3.6"), { env: ENFORCING })).response.headers.get("x-pkgguard-reference") ?? "");
      expect(seen.size).toBe(5);
      expect((await detections()).map((d) => d.reference)).toEqual(expect.arrayContaining([...seen]));
    });
    it("is recorded in observe-only mode too, so a would-be block can be found", async () => {
      const { response } = await run(tarball("event-stream", "3.3.6"), { env: { ENFORCE: "false" } });
      expect(response.headers.get("x-pkgguard-reference")).toBeNull();
      const [row] = await detections();
      expect(row?.verdict).toBe("flagged");
      expect(row?.reference).toMatch(REFERENCE);
    });
    it("is absent for a clean download and for a vulnerability that is only logged", async () => {
      await seed(lodashCve, "npm", "lodash");
      await run(tarball("left-pad", "1.3.0"), { env: ENFORCING });
      await run(tarball("lodash", "4.17.20"), { env: ENFORCING });
      expect((await detections()).map((d) => d.reference)).toEqual([null, null]);
    });
    it("gives npm a JSON error line, pip a reason phrase, and a browser the page", async () => {
      const asNpm = (await run(tarball("event-stream", "3.3.6"), { env: ENFORCING, headers: NPM_CLIENT })).response;
      expect(asNpm.headers.get("content-type")).toContain("application/json");
      expect(((await asNpm.json()) as { error: string }).error).toContain("osv.dev");
      const asPip = (await run(tarball("event-stream", "3.3.6"), { env: ENFORCING, headers: PIP_CLIENT })).response;
      expect(asPip.headers.get("content-type")).toContain("text/plain");
      expect(asPip.statusText).toMatch(/^Blocked by PkgGuard: event-stream@3\.3\.6 is listed as malware\. Ref PG-/);
      const asBrowser = (await run(tarball("event-stream", "3.3.6"), { env: ENFORCING, headers: { accept: "text/html" } })).response;
      expect(asBrowser.headers.get("content-type")).toContain("text/html");
    });
    it("uses the configured contact in what the developer is told", async () => {
      const { response } = await run(tarball("event-stream", "3.3.6"), { env: { ...ENFORCING, SUPPORT_CONTACT: "#sec-help" } });
      expect(await response.text()).toContain("Ask in #sec-help");
    });
  });

  it("observe-only: lets malware through and records it as flagged, never as blocked", async () => {
    const { response, next, upstream } = await run(tarball("event-stream", "3.3.6"), { env: { ENFORCE: "false" } });
    expect(response).toBe(upstream);
    expect(next).toHaveBeenCalledOnce();
    const [row] = await detections();
    expect(row).toMatchObject({ verdict: "flagged", reason: "osv-malware", osv_ids: "GHSA-mh6f-8j2x-4483" });
  });

  it.each(["", "TRUE", "1", "yes", " true"])("treats ENFORCE=%j as observe-only", async (value) => {
    const { response } = await run(tarball("event-stream", "3.3.6"), { env: { ENFORCE: value } });
    expect(response.status).toBe(200);
  });

  it("allows an unaffected version of a malicious package", async () => {
    const { response, next } = await run(tarball("event-stream", "3.3.5"), { env: ENFORCING });
    expect(response.status).toBe(200);
    expect(next).toHaveBeenCalledOnce();
    expect(await detections()).toEqual([expect.objectContaining({ verdict: "allowed", reason: null, source: "index" })]);
  });

  it("flags a vulnerable version but never blocks it, even when enforcing", async () => {
    const { response, next } = await run(tarball("lodash", "4.17.20"), { env: ENFORCING });
    expect(response.status).toBe(200);
    expect(next).toHaveBeenCalledOnce();
    const [row] = await detections();
    expect(row).toMatchObject({ verdict: "flagged", reason: "osv-cve", source: "index" });
    expect(row?.osv_ids).toContain("GHSA-35jh-r3h4-6jhm");
  });

  it("allows the fixed version of a vulnerable package", async () => {
    const { response } = await run(tarball("lodash", "4.17.21"), { env: ENFORCING });
    expect(response.status).toBe(200);
    expect(await detections()).toEqual([expect.objectContaining({ verdict: "allowed" })]);
  });

  it("looks the package up case-insensitively", async () => {
    const { response } = await run(`${NPM}/Event-Stream/-/Event-Stream-3.3.6.tgz`, { env: ENFORCING });
    expect(response.status).toBe(403);
  });

  it("blocks a PyPI sdist", async () => {
    const { response } = await run(`${PYPI}/ctx-0.1.2.tar.gz`, { env: ENFORCING });
    expect(response.status).toBe(403);
    const [row] = await detections();
    expect(row).toMatchObject({ ecosystem: "pypi", package_name: "ctx", reason: "osv-malware" });
  });

  it("blocks a scoped npm package", async () => {
    await env.PKG_INDEX.put(
      "npm:@scope/evil",
      JSON.stringify({ v: 1, m: [{ id: "MAL-2026-1", r: [], v: [], all: true }], c: [], u: "t" }),
    );
    const { response } = await run(`${NPM}/@scope/evil/-/evil-1.0.0.tgz`, { env: ENFORCING });
    expect(response.status).toBe(403);
    expect((await detections())[0]).toMatchObject({ package_name: "@scope/evil", purl: "pkg:npm/%40scope/evil@1.0.0" });
  });
});

describe("override lists", () => {
  const put = (mode: "allow" | "block", name: string, value: unknown) =>
    env.PKG_INDEX.put(`override:${mode}:npm:${name}`, JSON.stringify(value));

  beforeEach(() => seed(eventStream, "npm", "event-stream"));

  it("allow beats a malware verdict", async () => {
    await put("allow", "event-stream", { v: 1, versions: null });
    const { response, next } = await run(tarball("event-stream", "3.3.6"), { env: ENFORCING });
    expect(response.status).toBe(200);
    expect(next).toHaveBeenCalledOnce();
    expect(await detections()).toEqual([expect.objectContaining({ verdict: "allowed", reason: "override", source: "override" })]);
  });

  it("block stops a package the index knows nothing about", async () => {
    await put("block", "left-pad", { v: 1, versions: null });
    const { response, next } = await run(tarball("left-pad", "1.3.0"), { env: ENFORCING });
    expect(response.status).toBe(403);
    expect(next).not.toHaveBeenCalled();
    expect(await response.text()).toContain("An administrator has blocked this package");
    expect(await detections()).toEqual([expect.objectContaining({ verdict: "blocked", reason: "override", source: "override" })]);
  });

  it("block under ENFORCE=false is only flagged", async () => {
    await put("block", "left-pad", { v: 1, versions: null });
    const { response } = await run(tarball("left-pad", "1.3.0"));
    expect(response.status).toBe(200);
    expect((await detections())[0]).toMatchObject({ verdict: "flagged", reason: "override" });
  });

  it("allow beats block when both exist", async () => {
    await put("block", "left-pad", { v: 1, versions: null });
    await put("allow", "left-pad", { v: 1, versions: null });
    const { response } = await run(tarball("left-pad", "1.3.0"), { env: ENFORCING });
    expect(response.status).toBe(200);
  });

  it("a version-scoped override applies to those versions only", async () => {
    await put("block", "left-pad", { v: 1, versions: ["1.3.0"] });
    expect((await run(tarball("left-pad", "1.3.0"), { env: ENFORCING })).response.status).toBe(403);
    expect((await run(tarball("left-pad", "1.2.0"), { env: ENFORCING })).response.status).toBe(200);
  });

  it("ignores a malformed override instead of failing", async () => {
    await put("block", "left-pad", { v: 99 });
    expect((await run(tarball("left-pad", "1.3.0"), { env: ENFORCING })).response.status).toBe(200);
  });
});

describe("live OSV lookup on an index miss", () => {
  const osv = (body: unknown) => vi.spyOn(globalThis, "fetch").mockImplementation(async () => jsonResponse(body));

  it("sends a package-wide query to api.osv.dev with a timeout signal", async () => {
    const spy = osv({});
    await run(tarball("event-stream", "3.3.6"));
    expect(spy).toHaveBeenCalledOnce();
    const [url, init] = spy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.osv.dev/v1/query");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ package: { ecosystem: "npm", name: "event-stream" } });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("blocks malware that is not in the index yet, and caches it with a TTL", async () => {
    osv({ vulns: [eventStream] });
    const { response } = await run(tarball("event-stream", "3.3.6"), { env: ENFORCING });
    expect(response.status).toBe(403);
    expect((await detections())[0]).toMatchObject({ verdict: "blocked", reason: "osv-malware", source: "live-osv" });

    const cached = await env.PKG_INDEX.get<{ m: Array<{ id: string }> }>("npm:event-stream", "json");
    expect(cached?.m.map((a) => a.id)).toEqual(["GHSA-mh6f-8j2x-4483"]);
    const { keys } = await env.PKG_INDEX.list({ prefix: "npm:event-stream" });
    const ttl = (keys[0]?.expiration ?? 0) - Date.now() / 1000;
    expect(ttl).toBeGreaterThan(3500);
    expect(ttl).toBeLessThanOrEqual(3600);
  });

  it("remembers a clean answer, so the second request does not call OSV", async () => {
    const spy = osv({});
    expect((await run(tarball("left-pad", "1.3.0"), { env: ENFORCING })).response.status).toBe(200);
    expect(await env.PKG_INDEX.get("npm:left-pad", "json")).toMatchObject({ v: 1, n: true });
    expect((await run(tarball("left-pad", "1.3.0"), { env: ENFORCING })).response.status).toBe(200);
    expect(spy).toHaveBeenCalledOnce();
    expect((await detections()).map((d) => d.verdict)).toEqual(["allowed", "allowed"]);
  });

  it.each([
    ["a 500", () => vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("boom", { status: 500 }))],
    ["a 429", () => vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("slow down", { status: 429 }))],
    ["a network error", () => vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("network"))],
    ["a timeout", () => vi.spyOn(globalThis, "fetch").mockRejectedValue(new DOMException("timed out", "TimeoutError"))],
    ["unparseable JSON", () => vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("<html>", { status: 200 }))],
  ])("fails open on %s, records an error, and caches nothing", async (_name, arrange) => {
    arrange();
    const { response, next } = await run(tarball("left-pad", "1.3.0"), { env: ENFORCING });
    expect(response.status).toBe(200);
    expect(next).toHaveBeenCalledOnce();
    expect((await detections())[0]).toMatchObject({ verdict: "error", reason: "lookup-error", source: "live-osv" });
    expect(await env.PKG_INDEX.get("npm:left-pad")).toBeNull();
  });

  it("still blocks on what it did get when OSV paginates, but does not cache the partial answer", async () => {
    osv({ vulns: [eventStream], next_page_token: "more" });
    const { response } = await run(tarball("event-stream", "3.3.6"), { env: ENFORCING });
    expect(response.status).toBe(403);
    expect(await env.PKG_INDEX.get("npm:event-stream")).toBeNull();
  });

  it("does not cache a malformed answer as 'clean'", async () => {
    osv({ vulns: [{ id: 7 }] });
    await run(tarball("left-pad", "1.3.0"));
    expect(await env.PKG_INDEX.get("npm:left-pad")).toBeNull();
  });

  it("OSV_API_TIMEOUT_MS=0 disables the live lookup", async () => {
    const spy = osv({ vulns: [eventStream] });
    const { response } = await run(tarball("event-stream", "3.3.6"), { env: { ...ENFORCING, OSV_API_TIMEOUT_MS: "0" } });
    expect(response.status).toBe(200);
    expect(spy).not.toHaveBeenCalled();
  });

  it("falls back to a live lookup when the stored value is corrupt", async () => {
    await env.PKG_INDEX.put("npm:event-stream", JSON.stringify({ v: 1, m: "nope" }));
    const spy = osv({ vulns: [eventStream] });
    const { response } = await run(tarball("event-stream", "3.3.6"), { env: ENFORCING });
    expect(spy).toHaveBeenCalledOnce();
    expect(response.status).toBe(403);
  });

  it("does not call OSV when the index already answers", async () => {
    await seed(lodashCve, "npm", "lodash");
    const spy = osv({});
    await run(tarball("lodash", "4.17.21"));
    expect(spy).not.toHaveBeenCalled();
  });
});

describe("failing open", () => {
  const failingKv = {
    get: async () => {
      throw new Error("kv down");
    },
    put: async () => {},
  } as unknown as KVNamespace;

  it("passes the download through when KV is unavailable, and records an error", async () => {
    const { response, next } = await run(tarball("event-stream", "3.3.6"), { env: { ...ENFORCING, PKG_INDEX: failingKv } });
    expect(response.status).toBe(200);
    expect(next).toHaveBeenCalledOnce();
    expect((await detections())[0]).toMatchObject({ verdict: "error", reason: "lookup-error" });
  });

  it("is unaffected by a failing detections write", async () => {
    await seed(eventStream, "npm", "event-stream");
    const brokenDb = {
      prepare: () => {
        throw new Error("d1 down");
      },
    } as unknown as D1Database;
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const blocked = await run(tarball("event-stream", "3.3.6"), { env: { ...ENFORCING, DB: brokenDb } });
    expect(blocked.response.status).toBe(403);
    const passed = await run(tarball("event-stream", "3.3.5"), { env: { ...ENFORCING, DB: brokenDb } });
    expect(passed.response.status).toBe(200);
    expect(errors).toHaveBeenCalled();
  });

  it("is unaffected by a failing cache write", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => jsonResponse({}));
    const kv = {
      get: async () => null,
      put: async () => {
        throw new Error("kv write failed");
      },
    } as unknown as KVNamespace;
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { response } = await run(tarball("left-pad", "1.3.0"), { env: { ...ENFORCING, PKG_INDEX: kv } });
    expect(response.status).toBe(200);
  });

  it("does not wait on a hung identity lookup", async () => {
    await seed(eventStream, "npm", "event-stream");
    const started = Date.now();
    const { response } = await run(tarball("event-stream", "3.3.6"), {
      env: ENFORCING,
      identity: () => new Promise(() => {}),
    });
    expect(response.status).toBe(403);
    expect(Date.now() - started).toBeLessThan(2000);
    expect((await detections())[0]?.user_email).toBeNull();
  });

  it("records a null user when identity lookup rejects or finds nobody", async () => {
    await seed(eventStream, "npm", "event-stream");
    await run(tarball("event-stream", "3.3.6"), { identity: () => Promise.reject(new Error("no idp")) });
    await run(tarball("event-stream", "3.3.6"), { identity: async () => null });
    expect((await detections()).map((d) => d.user_email)).toEqual([null, null]);
  });
});

describe("next() discipline", () => {
  it("calls next exactly once on every pass-through path and never on a block", async () => {
    await seed(eventStream, "npm", "event-stream");
    vi.spyOn(globalThis, "fetch").mockImplementation(async () => jsonResponse({}));
    const cases: Array<[string, number]> = [
      [`${NPM}/lodash`, 1],
      [tarball("event-stream", "3.3.5"), 1],
      [tarball("left-pad", "1.3.0"), 1],
      [tarball("event-stream", "3.3.6"), 0],
    ];
    for (const [url, calls] of cases) {
      const { next } = await run(url, { env: ENFORCING });
      expect(next, url).toHaveBeenCalledTimes(calls);
    }
  });
});

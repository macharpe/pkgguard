import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { ENFORCEMENT_KEY, ENFORCEMENT_REFRESH_MS, ENFORCEMENT_RETRY_MS, parseEnforcementText, type OsvRecord } from "@pkgguard/core";
import eventStreamJson from "../../../packages/core/test/fixtures/GHSA-mh6f-8j2x-4483.json";
import { GatewayMiddleware } from "../src/index.js";
import type { Env } from "../src/env.js";
import { reportEnforcement, resetEnforcementReport } from "../src/report.js";
import { detections, gatewayContext, reset, run, seed, tarball } from "./harness.js";

const eventStream = eventStreamJson as unknown as OsvRecord;
const T0 = Date.parse("2026-11-09T10:00:00.000Z");
const HOUR = ENFORCEMENT_REFRESH_MS;

beforeEach(async () => {
  await reset();
  resetEnforcementReport();
});

interface FakeKv {
  kv: Pick<KVNamespace, "get" | "put">;
  store: Map<string, string>;
  gets: number;
  puts: number;
  failGet: boolean;
  failPut: boolean;
}
function fakeKv(initial?: string): FakeKv {
  const state = { store: new Map<string, string>(), gets: 0, puts: 0, failGet: false, failPut: false } as FakeKv;
  if (initial !== undefined) state.store.set(ENFORCEMENT_KEY, initial);
  state.kv = {
    get: async (key: string) => {
      state.gets++;
      if (state.failGet) throw new Error("kv down");
      return state.store.get(key) ?? null;
    },
    put: async (key: string, value: string) => {
      state.puts++;
      if (state.failPut) throw new Error("kv down");
      state.store.set(key, value);
    },
  } as unknown as Pick<KVNamespace, "get" | "put">;
  return state;
}

const settings = (enforce: boolean, observeOnly: Array<"npm" | "pypi" | "cargo" | "rubygems" | "nuget" | "go"> = []) => ({ enforce, observeOnly: new Set(observeOnly) });
const stored = (state: FakeKv) => parseEnforcementText(state.store.get(ENFORCEMENT_KEY) ?? null);
const reportJson = (enforce: boolean, observeOnly: string[], atMs: number) => JSON.stringify({ enforce, observeOnly, reportedAt: new Date(atMs).toISOString() });

describe("reportEnforcement", () => {
  it("writes the settings and the time on the first call", async () => {
    const k = fakeKv();
    expect(await reportEnforcement(k.kv, settings(true, ["pypi"]), T0)).toBe("written");
    expect(stored(k)).toEqual({ enforce: true, observeOnly: ["pypi"], reportedAt: new Date(T0).toISOString() });
  });

  it("writes enforce=false for observe-only, not an absent report", async () => {
    const k = fakeKv();
    await reportEnforcement(k.kv, settings(false), T0);
    expect(stored(k)?.enforce).toBe(false);
  });

  it("does not write when the stored report matches and is fresh", async () => {
    const k = fakeKv(reportJson(true, ["pypi"], T0 - 10 * 60_000));
    expect(await reportEnforcement(k.kv, settings(true, ["pypi"]), T0)).toBe("unchanged");
    expect(k.puts).toBe(0);
    expect(k.gets).toBe(1);
  });

  it("does no KV work at all on later calls from the same isolate", async () => {
    const k = fakeKv();
    await reportEnforcement(k.kv, settings(true), T0);
    const [gets, puts] = [k.gets, k.puts];
    for (const offset of [1_000, 60_000, HOUR - 1]) expect(await reportEnforcement(k.kv, settings(true), T0 + offset)).toBe("skipped");
    expect([k.gets, k.puts]).toEqual([gets, puts]);
  });

  it("does no KV work either when it only confirmed an existing report", async () => {
    const k = fakeKv(reportJson(true, [], T0 - 60_000));
    await reportEnforcement(k.kv, settings(true), T0);
    expect(await reportEnforcement(k.kv, settings(true), T0 + 60_000)).toBe("skipped");
    expect(k.gets).toBe(1);
  });

  it("writes when enforce changed, even though the stored report is fresh", async () => {
    const k = fakeKv(reportJson(true, [], T0 - 1000));
    expect(await reportEnforcement(k.kv, settings(false), T0)).toBe("written");
    expect(stored(k)?.enforce).toBe(false);
  });

  it("writes when the observe-only list changed", async () => {
    const k = fakeKv(reportJson(true, ["pypi"], T0 - 1000));
    expect(await reportEnforcement(k.kv, settings(true, ["pypi", "go"]), T0)).toBe("written");
    expect(stored(k)?.observeOnly).toEqual(["pypi", "go"]);
    expect(await reportEnforcement(fakeKv(reportJson(true, ["pypi"], T0)).kv, settings(true, []), T0 + 1)).toBe("written");
  });

  it("re-checks a changed setting in an isolate that already reported", async () => {
    const k = fakeKv();
    await reportEnforcement(k.kv, settings(true), T0);
    expect(await reportEnforcement(k.kv, settings(false), T0 + 1000)).toBe("written");
    expect(stored(k)?.enforce).toBe(false);
  });

  it("refreshes a stored report once it is older than the interval", async () => {
    const k = fakeKv(reportJson(true, [], T0 - HOUR - 1));
    expect(await reportEnforcement(k.kv, settings(true), T0)).toBe("written");
    expect(stored(k)?.reportedAt).toBe(new Date(T0).toISOString());
  });

  it("keeps a stored report that is just inside the interval", async () => {
    const k = fakeKv(reportJson(true, [], T0 - HOUR + 1));
    expect(await reportEnforcement(k.kv, settings(true), T0)).toBe("unchanged");
  });

  it("repeats its own report after the interval", async () => {
    const k = fakeKv();
    await reportEnforcement(k.kv, settings(true), T0);
    expect(await reportEnforcement(k.kv, settings(true), T0 + HOUR)).toBe("written");
    expect(stored(k)?.reportedAt).toBe(new Date(T0 + HOUR).toISOString());
  });

  it.each(["{not json", "[]", "null", "", JSON.stringify({ enforce: "true", observeOnly: [], reportedAt: new Date(T0).toISOString() })])("replaces an unreadable stored value %j", async (text) => {
    const k = fakeKv(text);
    expect(await reportEnforcement(k.kv, settings(true), T0)).toBe("written");
    expect(stored(k)?.enforce).toBe(true);
  });

  it("never throws when the read fails, and backs off before trying again", async () => {
    const k = fakeKv();
    k.failGet = true;
    expect(await reportEnforcement(k.kv, settings(true), T0)).toBe("failed");
    expect(k.puts).toBe(0);
    expect(await reportEnforcement(k.kv, settings(true), T0 + ENFORCEMENT_RETRY_MS - 1)).toBe("skipped");
    expect(k.gets).toBe(1);
    k.failGet = false;
    expect(await reportEnforcement(k.kv, settings(true), T0 + ENFORCEMENT_RETRY_MS)).toBe("written");
  });

  it("never throws when the write fails, and does not claim it succeeded", async () => {
    const k = fakeKv();
    k.failPut = true;
    expect(await reportEnforcement(k.kv, settings(true), T0)).toBe("failed");
    k.failPut = false;
    expect(await reportEnforcement(k.kv, settings(true), T0 + ENFORCEMENT_RETRY_MS)).toBe("written");
    expect(stored(k)?.enforce).toBe(true);
  });
});

/** The real KV, with the report key observable. Everything else passes through. */
function observedKv(over: { get?: (key: string) => Promise<string | null>; put?: (key: string, value: string) => Promise<void> } = {}) {
  const calls = { get: 0, put: 0 };
  const real = env.PKG_INDEX;
  const kv = new Proxy(real, {
    get(target, prop) {
      if (prop === "get")
        return (key: string, ...rest: unknown[]) => {
          if (key !== ENFORCEMENT_KEY) return (target.get as (...a: unknown[]) => unknown)(key, ...rest);
          calls.get++;
          return over.get ? over.get(key) : target.get(key);
        };
      if (prop === "put")
        return (key: string, value: string, ...rest: unknown[]) => {
          if (key !== ENFORCEMENT_KEY) return (target.put as (...a: unknown[]) => unknown)(key, value, ...rest);
          calls.put++;
          return over.put ? over.put(key, value) : target.put(key, value);
        };
      const value = Reflect.get(target, prop);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { kv, calls };
}

const reported = async () => parseEnforcementText(await env.PKG_INDEX.get(ENFORCEMENT_KEY));

describe("what GatewayMiddleware reports", () => {
  it("records ENFORCE=true as enforcing", async () => {
    await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: "true" } });
    expect(await reported()).toMatchObject({ enforce: true, observeOnly: [] });
  });

  it.each(["false", "", "TRUE", "1", "yes", " true"])("records ENFORCE=%j as observe-only, exactly as the Worker reads it", async (value) => {
    await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: value } });
    expect((await reported())?.enforce).toBe(false);
  });

  it("records the observe-only ecosystems and drops an id it does not know", async () => {
    await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: "true", OBSERVE_ONLY: "go, pypi,pipy" } });
    expect((await reported())?.observeOnly).toEqual(["pypi", "go"]);
  });

  it("stamps the time it reported", async () => {
    const before = Date.now();
    await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: "true" } });
    const at = Date.parse((await reported())?.reportedAt ?? "");
    expect(at).toBeGreaterThanOrEqual(before);
    expect(at).toBeLessThanOrEqual(Date.now());
  });

  it("reads KV for the report once per isolate, not once per request", async () => {
    const { kv, calls } = observedKv();
    for (let i = 0; i < 4; i++) await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: "true", PKG_INDEX: kv } });
    expect(calls).toEqual({ get: 1, put: 1 });
  });
});

describe("the report never affects a download", () => {
  const broken = () =>
    observedKv({
      get: async () => {
        throw new Error("kv read failed");
      },
      put: async () => {
        throw new Error("kv write failed");
      },
    });

  it("still blocks, calls no next(), and records the detection when KV fails for the report", async () => {
    await seed(eventStream, "npm", "event-stream");
    const { response, next } = await run(tarball("event-stream", "3.3.6"), { env: { ENFORCE: "true", PKG_INDEX: broken().kv } });
    expect(response.status).toBe(403);
    expect(next).not.toHaveBeenCalled();
    expect(await detections()).toEqual([expect.objectContaining({ verdict: "blocked", reason: "osv-malware" })]);
  });

  it("still calls next() exactly once and returns the upstream response when KV fails for the report", async () => {
    const { response, next, upstream } = await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: "true", PKG_INDEX: broken().kv } });
    expect(response).toBe(upstream);
    expect(next).toHaveBeenCalledOnce();
  });

  it("calls next() exactly once on a clean download while it reports", async () => {
    const { next } = await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: "true" } });
    expect(next).toHaveBeenCalledOnce();
  });

  it("does not wait for the report before returning the response", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { kv, calls } = observedKv({ get: async () => (await gate, null) });
    const ctx = createExecutionContext();
    const middleware = new GatewayMiddleware(ctx, { ...env, ENFORCE: "true", PKG_INDEX: kv } as Env);
    let nextCalls = 0;
    const response = await middleware.handle(new Request(tarball("left-pad", "1.3.0")), gatewayContext(), async () => (nextCalls++, new Response("ok")));
    expect(response.status).toBe(200);
    expect(nextCalls).toBe(1);
    expect(calls).toEqual({ get: 1, put: 0 });
    expect(await reported()).toBeNull();
    release();
    await waitOnExecutionContext(ctx);
    expect(await reported()).toMatchObject({ enforce: true });
  });

  it("does not report from traffic the Worker does not recognise", async () => {
    const { kv, calls } = observedKv();
    await run("https://registry.npmjs.org/lodash", { env: { ENFORCE: "true", PKG_INDEX: kv } });
    expect(calls).toEqual({ get: 0, put: 0 });
  });
});

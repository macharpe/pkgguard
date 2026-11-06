import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CSRF_HEADER, runScheduled } from "../src/index.js";
import { NOW_MS } from "./jwt-helpers.js";
import { adminEnv, call, failNextWorkflowCreate, serviceToken, setup, user, workflowCalls } from "./harness.js";

beforeEach(setup);
const body = async (r: Response) => (await r.json()) as any;
const post = async (token: string | null, headers: Record<string, string> = { [CSRF_HEADER]: "1" }, path = "/api/refresh") => call(path, token, { method: "POST", headers });
const run = (id: string, status: string, over: Record<string, unknown> = {}) =>
  env.DB.prepare("INSERT INTO refresh_runs (id, kind, trigger, status, phase, items_done, items_total, started_at) VALUES (?, 'manual', 'x', ?, 'p', ?, ?, ?)")
    .bind(id, status, over["done"] ?? 0, over["total"] ?? 0, over["startedAt"] ?? new Date(NOW_MS - 60_000).toISOString()).run();
const ID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ID_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

describe("POST /api/refresh", () => {
  it("starts a manual run: 202 with the run id, a queued row, and a Workflow started under that id", async () => {
    const r = await post(await user());
    expect(r.status).toBe(202);
    const { runId } = await body(r);
    expect(runId).toMatch(/^[0-9a-f-]{36}$/);
    expect(await env.DB.prepare("SELECT kind, trigger, status FROM refresh_runs WHERE id = ?").bind(runId).first()).toEqual({ kind: "manual", trigger: "demo@example.com", status: "queued" });
    expect(workflowCalls).toEqual([{ id: runId, params: { kind: "manual", trigger: "demo@example.com" } }]);
  });
  it("records who started it in the audit log", async () => {
    const { runId } = await body(await post(await user(undefined, "ops@example.com")));
    expect(await env.DB.prepare("SELECT actor, action, detail FROM audit_log").first()).toEqual({ actor: "ops@example.com", action: "refresh.start", detail: runId });
  });
  it("lets a service token start a run, and records it as such", async () => {
    const r = await post(await serviceToken());
    expect(r.status).toBe(202);
    expect((await env.DB.prepare("SELECT trigger FROM refresh_runs").first<{ trigger: string }>())?.trigger).toBe("service-token:tok123.access");
  });
  it("refuses with 409 while a run is active, naming it, and starts nothing", async () => {
    await run(ID_A, "running");
    const r = await post(await user());
    expect(r.status).toBe(409);
    expect(await body(r)).toEqual({ error: "a refresh is already running", runId: ID_A });
    expect(workflowCalls).toEqual([]);
  });
  it("lets exactly one of several simultaneous requests through", async () => {
    const token = await user();
    const results = await Promise.all(Array.from({ length: 6 }, () => post(token)));
    expect(results.filter((r) => r.status === 202)).toHaveLength(1);
    expect(results.filter((r) => r.status === 409)).toHaveLength(5);
    expect(workflowCalls).toHaveLength(1);
  });
  it("fails with a generic 500 and frees the slot when the Workflow cannot be started", async () => {
    failNextWorkflowCreate.value = true;
    const r = await post(await user());
    expect(r.status).toBe(500);
    expect(await r.text()).toBe('{"error":"internal error"}');
    expect(await env.DB.prepare("SELECT status, phase FROM refresh_runs").first()).toEqual({ status: "failed", phase: "failed to start" });
    expect((await post(await user())).status).toBe(202); // not blocked by the dead run
  });
});

describe("CSRF and authentication on writes", () => {
  it("requires authentication first: 401 with no token, with or without the header, so callers learn nothing about the CSRF scheme", async () => {
    expect((await post(null)).status).toBe(401);
    expect((await post(null, {})).status).toBe(401);
    expect((await post("garbage", {})).status).toBe(403);
  });
  it("rejects a write without the CSRF header, so a page on another origin cannot start one", async () => {
    const r = await post(await user(), {});
    expect(r.status).toBe(403);
    expect(await body(r)).toEqual({ error: "missing CSRF header" });
    expect(workflowCalls).toEqual([]);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM refresh_runs").first()).toEqual({ n: 0 });
  });
  it.each(["0", "true", "", "yes"])("rejects a CSRF header of %j", async (value) => {
    expect((await post(await user(), { [CSRF_HEADER]: value })).status).toBe(403);
  });
  it("ignores an Origin header: the custom header is what counts", async () => {
    expect((await post(await user(), { origin: "https://evil.example" })).status).toBe(403);
    expect((await post(await user(), { origin: "https://evil.example", [CSRF_HEADER]: "1" })).status).toBe(202);
  });
  it("still refuses a bad token before looking at the CSRF header", async () => {
    expect((await post("garbage")).status).toBe(403);
  });
  it("does not require the header for reads", async () => {
    expect((await call("/api/refresh/history", await user())).status).toBe(200);
  });
  it("allows only POST on /api/refresh; other methods and paths are 405", async () => {
    const token = await user();
    for (const method of ["PUT", "DELETE", "PATCH"]) expect((await call("/api/refresh", token, { method, headers: { [CSRF_HEADER]: "1" } })).status, method).toBe(405);
    expect((await post(token, { [CSRF_HEADER]: "1" }, "/api/refresh/history")).status).toBe(405);
    expect((await post(token, { [CSRF_HEADER]: "1" }, `/api/refresh/${ID_A}`)).status).toBe(405);
    expect((await post(token, { [CSRF_HEADER]: "1" }, "/api/status")).status).toBe(405);
  });
  it("answers GET /api/refresh itself with 404: there is nothing to list there", async () => {
    expect((await call("/api/refresh", await user())).status).toBe(404);
  });
});

describe("GET /api/refresh/:id", () => {
  it("returns the run with an ETA while it is running", async () => {
    await run(ID_A, "running", { done: 25, total: 100, startedAt: new Date(NOW_MS - 50_000).toISOString() });
    const r = await body(await call(`/api/refresh/${ID_A}`, await user()));
    expect(r).toMatchObject({ id: ID_A, status: "running", items_done: 25, items_total: 100, phase: "p", etaSeconds: 150 });
  });
  it("has no ETA once it is finished", async () => {
    await run(ID_A, "complete", { done: 100, total: 100 });
    expect((await body(await call(`/api/refresh/${ID_A}`, await user()))).etaSeconds).toBeNull();
  });
  it("404s an unknown run", async () => {
    expect((await call(`/api/refresh/${ID_B}`, await user())).status).toBe(404);
  });
  it.each(["nope", "history2", "123", `${ID_A}x`, "%2e%2e", "..", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", ""])("404s a malformed id %j without touching the database", async (id) => {
    let queries = 0;
    const counting = new Proxy(env.DB, { get: (t, p) => (p === "prepare" ? (...a: unknown[]) => (queries++, (t.prepare as (...x: unknown[]) => unknown)(...a)) : Reflect.get(t, p, t)) }) as D1Database;
    const r = await call(`/api/refresh/${id}`, await user(), {}, adminEnv({ DB: counting }));
    expect(r.status).toBe(404);
    expect(queries).toBe(0);
  });
  it("requires authentication", async () => {
    expect((await call(`/api/refresh/${ID_A}`, null)).status).toBe(401);
  });
});

describe("GET /api/refresh/history", () => {
  it("lists runs newest first, limited", async () => {
    await run(ID_A, "complete", { startedAt: "2026-11-01T00:00:00Z" });
    await run(ID_B, "complete", { startedAt: "2026-11-03T00:00:00Z" });
    expect((await body(await call("/api/refresh/history", await user()))).items.map((i: { id: string }) => i.id)).toEqual([ID_B, ID_A]);
    expect((await body(await call("/api/refresh/history?limit=1", await user()))).items).toHaveLength(1);
  });
  it.each(["?limit=0", "?limit=51", "?limit=abc", "?limit=-1"])("rejects %s with 400", async (qs) => {
    expect((await call(`/api/refresh/history${qs}`, await user())).status).toBe(400);
  });
  it("is empty, not an error, with no runs", async () => {
    expect(await body(await call("/api/refresh/history", await user()))).toEqual({ items: [] });
  });
});

describe("scheduled runs", () => {
  const cron = (expr: string) => runScheduled({ cron: expr, scheduledTime: NOW_MS }, adminEnv());
  const rows = async () => (await env.DB.prepare("SELECT kind, trigger, status, started_at FROM refresh_runs").all<{ kind: string; trigger: string; status: string; started_at: string }>()).results;

  it("the monthly schedule starts a monthly run triggered by cron, at the scheduled time", async () => {
    await cron("0 3 1 * *");
    expect(await rows()).toEqual([{ kind: "monthly", trigger: "cron", status: "queued", started_at: new Date(NOW_MS).toISOString() }]);
    expect(workflowCalls).toHaveLength(1);
  });
  it("the daily schedule starts a daily run", async () => {
    await cron("0 4 * * *");
    expect((await rows())[0]?.kind).toBe("daily");
  });
  it("ignores an unknown schedule and says so", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    await cron("5 5 5 5 5");
    expect(await rows()).toEqual([]);
    expect(workflowCalls).toEqual([]);
    expect(spy).toHaveBeenCalledWith("unknown cron schedule", "5 5 5 5 5");
    spy.mockRestore();
  });
  it("skips quietly when a run is already active, rather than queueing a second", async () => {
    await run(ID_A, "running", { startedAt: new Date(NOW_MS - 60_000).toISOString() });
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    await cron("0 4 * * *");
    expect(await rows()).toHaveLength(1);
    expect(workflowCalls).toEqual([]);
    expect(spy).toHaveBeenCalledWith("refresh skipped: one is already running", ID_A);
    spy.mockRestore();
  });
  it("marks the run failed and surfaces the error when the Workflow cannot start", async () => {
    failNextWorkflowCreate.value = true;
    await expect(cron("0 4 * * *")).rejects.toThrow("workflow service unavailable");
    expect((await rows())[0]?.status).toBe("failed");
  });
});

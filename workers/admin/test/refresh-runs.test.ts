import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { ACTIVE_RUN_MAX_AGE_MS, etaSeconds, getRun, listRuns, startRun, updateRun, type RunPatch } from "../src/refresh/runs.js";

const NOW = new Date("2026-11-07T12:00:00Z");
const clear = () => env.DB.exec("DELETE FROM refresh_runs");
beforeEach(clear);

const seed = (id: string, status: string, startedAt: string) =>
  env.DB.prepare("INSERT INTO refresh_runs (id, kind, trigger, status, started_at) VALUES (?, 'manual', 'x', ?, ?)").bind(id, status, startedAt).run();

describe("startRun", () => {
  it("starts a run when none is active, queued, with its trigger", async () => {
    expect(await startRun(env.DB, { id: "r1", kind: "manual", trigger: "me@example.com" }, NOW)).toEqual({ started: true });
    expect(await getRun(env.DB, "r1")).toMatchObject({ id: "r1", kind: "manual", trigger: "me@example.com", status: "queued", phase: "queued", items_done: 0, finished_at: null, started_at: NOW.toISOString() });
  });
  it.each(["queued", "running"])("refuses while a %s run is active, naming it", async (status) => {
    await seed("busy", status, new Date(NOW.getTime() - 60_000).toISOString());
    expect(await startRun(env.DB, { id: "r2", kind: "manual", trigger: "x" }, NOW)).toEqual({ started: false, activeId: "busy" });
    expect(await getRun(env.DB, "r2")).toBeNull();
  });
  it.each(["complete", "failed"])("is not blocked by a %s run", async (status) => {
    await seed("done", status, new Date(NOW.getTime() - 60_000).toISOString());
    expect(await startRun(env.DB, { id: "r2", kind: "daily", trigger: "cron" }, NOW)).toEqual({ started: true });
  });
  it("presumes a run active for over three hours is dead, so a crashed Workflow cannot block refreshes forever", async () => {
    await seed("stale", "running", new Date(NOW.getTime() - ACTIVE_RUN_MAX_AGE_MS - 1000).toISOString());
    expect(await startRun(env.DB, { id: "r2", kind: "manual", trigger: "x" }, NOW)).toEqual({ started: true });
  });
  it("still honours a run just inside the three-hour window", async () => {
    await seed("recent", "running", new Date(NOW.getTime() - ACTIVE_RUN_MAX_AGE_MS + 60_000).toISOString());
    expect((await startRun(env.DB, { id: "r2", kind: "manual", trigger: "x" }, NOW)).started).toBe(false);
  });
  it("lets exactly one of several simultaneous starts win", async () => {
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => startRun(env.DB, { id: `race-${i}`, kind: "manual", trigger: "x" }, NOW)));
    expect(results.filter((r) => r.started)).toHaveLength(1);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM refresh_runs").first<{ n: number }>())?.n).toBe(1);
  });
  it("rejects a duplicate run id", async () => {
    await startRun(env.DB, { id: "dup", kind: "manual", trigger: "x" }, NOW);
    await env.DB.prepare("UPDATE refresh_runs SET status = 'complete' WHERE id = 'dup'").run();
    await expect(startRun(env.DB, { id: "dup", kind: "manual", trigger: "x" }, NOW)).rejects.toThrow();
  });
});

describe("updateRun", () => {
  it("updates only the fields given", async () => {
    await startRun(env.DB, { id: "u1", kind: "manual", trigger: "x" }, NOW);
    await updateRun(env.DB, "u1", { status: "running", items_total: 50 });
    expect(await getRun(env.DB, "u1")).toMatchObject({ status: "running", items_total: 50, items_done: 0, phase: "queued" });
  });
  it("can set a value to null", async () => {
    await startRun(env.DB, { id: "u1", kind: "manual", trigger: "x" }, NOW);
    await updateRun(env.DB, "u1", { phase: null });
    expect((await getRun(env.DB, "u1"))?.phase).toBeNull();
  });
  it("is a no-op for an empty patch", async () => {
    await startRun(env.DB, { id: "u1", kind: "manual", trigger: "x" }, NOW);
    await expect(updateRun(env.DB, "u1", {})).resolves.toBeUndefined();
  });
  it("cannot write a column outside the whitelist, even if one is smuggled in", async () => {
    await startRun(env.DB, { id: "u1", kind: "manual", trigger: "x" }, NOW);
    await updateRun(env.DB, "u1", { id: "hijacked", trigger: "evil", "status = 'x', phase": "y" } as unknown as RunPatch);
    expect(await getRun(env.DB, "u1")).toMatchObject({ id: "u1", trigger: "x", status: "queued" });
  });
  it("does not throw for a missing run", async () => {
    await expect(updateRun(env.DB, "nope", { status: "failed" })).resolves.toBeUndefined();
  });
});

describe("listRuns", () => {
  it("returns newest first, limited", async () => {
    for (const [id, at] of [["a", "2026-11-01T00:00:00Z"], ["b", "2026-11-03T00:00:00Z"], ["c", "2026-11-02T00:00:00Z"]] as const) await seed(id, "complete", at);
    expect((await listRuns(env.DB, 10)).map((r) => r.id)).toEqual(["b", "c", "a"]);
    expect((await listRuns(env.DB, 2)).map((r) => r.id)).toEqual(["b", "c"]);
  });
});

describe("etaSeconds", () => {
  const run = (over: Partial<Parameters<typeof etaSeconds>[0]> = {}) => ({ status: "running" as const, items_done: 25, items_total: 100, started_at: new Date(NOW.getTime() - 50_000).toISOString(), ...over });
  it("extrapolates from the rate so far", () => {
    expect(etaSeconds(run(), NOW)).toBe(150); // 25 in 50s -> 75 left at 0.5/s
  });
  it.each([
    ["not running", { status: "complete" as const }],
    ["nothing done yet", { items_done: 0 }],
    ["already finished", { items_done: 100 }],
    ["over-counted", { items_done: 120 }],
    ["no clock progress", { started_at: NOW.toISOString() }],
    ["bad timestamp", { started_at: "garbage" }],
    ["starts in the future", { started_at: new Date(NOW.getTime() + 5000).toISOString() }],
  ])("is null when %s", (_n, over) => {
    expect(etaSeconds(run(over), NOW)).toBeNull();
  });
});

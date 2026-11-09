import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { BATCH_SIZE, processBatch } from "../src/refresh/batch.js";
import { MAX_DELTA, PlanError, advanceHighWater, planRun } from "../src/refresh/plan.js";
import { OSV_BASE, type FetchLike } from "../src/refresh/osv-fetch.js";

const RUN = "run-1";
const NOW = "2026-11-07T00:00:00Z";
const csvUrl = (dir: string) => `${OSV_BASE}/${dir}/modified_id.csv`;
const recUrl = (dir: string, id: string) => `${OSV_BASE}/${dir}/${id}.json`;
const pkg = (ecosystem: string, name: string) => ({ package: { ecosystem, name }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] });
const rec = (id: string, modified: string, name = id.toLowerCase(), ecosystem = "npm") => ({ id, modified, summary: "s", affected: [pkg(ecosystem, name)] });

interface Routes {
  [url: string]: Response | (() => Response);
}
const router = (routes: Routes, calls: string[] = []): FetchLike => async (url) => {
  calls.push(url);
  // The other ecosystems are enabled too, and most of these tests are about npm and PyPI: unless a test routes them, they have nothing new.
  const hit = routes[url] ?? (["crates.io", "RubyGems", "NuGet", "Go"].some((dir) => url === csvUrl(dir)) ? csv() : undefined);
  if (hit === undefined) return new Response("", { status: 404 });
  return typeof hit === "function" ? hit() : hit.clone();
};
const csv = (...lines: string[]) => new Response(lines.join("\n") + "\n");

const seedState = async (npm: string, pypi: string) => {
  await env.DB.exec("DELETE FROM sync_state");
  await env.DB.prepare("INSERT INTO sync_state (ecosystem, last_modified, record_count, last_synced_at) VALUES ('npm', ?, 10, '2026-11-01T00:00:00Z'), ('pypi', ?, 20, '2026-11-01T00:00:00Z'), ('cargo', ?, 30, '2026-11-01T00:00:00Z'), ('rubygems', ?, 40, '2026-11-01T00:00:00Z'), ('nuget', ?, 50, '2026-11-01T00:00:00Z'), ('go', ?, 60, '2026-11-01T00:00:00Z')").bind(npm, pypi, pypi, pypi, pypi, pypi).run();
};
const items = async (run = RUN) => (await env.DB.prepare("SELECT seq, ecosystem, osv_id, modified, status FROM refresh_items WHERE run_id = ? ORDER BY seq").bind(run).all<{ seq: number; ecosystem: string; osv_id: string; modified: string; status: string }>()).results;
const state = async (eco: string) => env.DB.prepare("SELECT last_modified, record_count, last_synced_at FROM sync_state WHERE ecosystem = ?").bind(eco).first<{ last_modified: string; record_count: number; last_synced_at: string }>();
const insertItems = async (rows: Array<[number, string, string, string, string?]>) => {
  if (rows.length === 0) return;
  await env.DB.batch(rows.map(([seq, eco, id, modified, status]) => env.DB.prepare("INSERT INTO refresh_items (run_id, seq, ecosystem, osv_id, modified, status) VALUES (?,?,?,?,?,?)").bind(RUN, seq, eco, id, modified, status ?? "pending")));
};
beforeEach(async () => {
  await env.DB.batch([env.DB.prepare("DELETE FROM refresh_items"), env.DB.prepare("DELETE FROM advisories"), env.DB.prepare("DELETE FROM refresh_runs")]);
  const kv = await env.PKG_INDEX.list();
  await Promise.all(kv.keys.map((k) => env.PKG_INDEX.delete(k.name)));
  await seedState("2026-11-05T00:00:00Z", "2026-11-05T00:00:00Z");
});

describe("planRun", () => {
  it("stores what changed since each high-water mark, oldest first, across both ecosystems", async () => {
    const f = router({
      [csvUrl("npm")]: csv("2026-11-06T12:00:00Z,GHSA-n3", "2026-11-06T08:00:00Z,GHSA-n2", "2026-11-04T00:00:00Z,GHSA-old"),
      [csvUrl("PyPI")]: csv("2026-11-06T10:00:00Z,PYSEC-p2", "2026-11-05T01:00:00Z,PYSEC-p1"),
    });
    expect(await planRun({ db: env.DB, fetch: f }, RUN)).toEqual({ total: 4 });
    const rows = await items();
    expect(rows.map((r) => `${r.seq}:${r.ecosystem}:${r.osv_id}`)).toEqual(["0:pypi:PYSEC-p1", "1:npm:GHSA-n2", "2:pypi:PYSEC-p2", "3:npm:GHSA-n3"]);
    expect(rows.every((r) => r.status === "pending")).toBe(true);
  });
  it("orders mixed-precision timestamps chronologically, not lexically", async () => {
    const f = router({
      [csvUrl("npm")]: csv("2026-11-06T11:30:04Z,GHSA-whole", "2026-11-06T11:30:04.4Z,GHSA-frac"),
      [csvUrl("PyPI")]: csv(),
    });
    await planRun({ db: env.DB, fetch: f }, RUN);
    expect((await items()).map((r) => r.osv_id)).toEqual(["GHSA-whole", "GHSA-frac"]);
  });
  it("includes the boundary record, so the last one seen is re-fetched rather than risked", async () => {
    await seedState("2026-11-06T00:00:00.5Z", "2026-11-06T00:00:00Z");
    const f = router({ [csvUrl("npm")]: csv("2026-11-06T00:00:00.5Z,GHSA-edge", "2026-11-06T00:00:00.4Z,GHSA-before"), [csvUrl("PyPI")]: csv() });
    await planRun({ db: env.DB, fetch: f }, RUN);
    expect((await items()).map((r) => r.osv_id)).toEqual(["GHSA-edge"]);
  });
  it("records OSV's record count, not the delta size", async () => {
    const f = router({ [csvUrl("npm")]: csv("2026-11-06T12:00:00Z,A-1", "2026-11-01T00:00:00Z,A-2", "2026-11-01T00:00:00Z,A-3"), [csvUrl("PyPI")]: csv("2026-11-01T00:00:00Z,B-1") });
    await planRun({ db: env.DB, fetch: f }, RUN);
    expect((await state("npm"))?.record_count).toBe(3);
    expect((await state("pypi"))?.record_count).toBe(1);
  });
  it("updates the run's total and phase, and says so when there is nothing to do", async () => {
    await env.DB.prepare("INSERT INTO refresh_runs (id, kind, trigger, status, started_at) VALUES (?, 'manual', 'x', 'running', ?)").bind(RUN, NOW).run();
    await planRun({ db: env.DB, fetch: router({ [csvUrl("npm")]: csv(), [csvUrl("PyPI")]: csv() }) }, RUN);
    expect(await env.DB.prepare("SELECT items_total, phase FROM refresh_runs WHERE id = ?").bind(RUN).first()).toEqual({ items_total: 0, phase: "nothing to do" });
    await planRun({ db: env.DB, fetch: router({ [csvUrl("npm")]: csv("2026-11-06T00:00:00Z,X-1"), [csvUrl("PyPI")]: csv() }) }, RUN);
    expect(await env.DB.prepare("SELECT items_total, phase FROM refresh_runs WHERE id = ?").bind(RUN).first()).toEqual({ items_total: 1, phase: "fetching records" });
  });
  it("replaces the list when the step is retried, rather than duplicating it", async () => {
    const f = router({ [csvUrl("npm")]: csv("2026-11-06T00:00:00Z,X-1", "2026-11-06T01:00:00Z,X-2"), [csvUrl("PyPI")]: csv() });
    await planRun({ db: env.DB, fetch: f }, RUN);
    await planRun({ db: env.DB, fetch: f }, RUN);
    expect(await items()).toHaveLength(2);
  });
  it("keeps other runs' lists untouched", async () => {
    await insertItems([[0, "npm", "KEEP-1", "2026-11-06T00:00:00Z"]]);
    await env.DB.prepare("UPDATE refresh_items SET run_id = 'other'").run();
    await planRun({ db: env.DB, fetch: router({ [csvUrl("npm")]: csv("2026-11-06T00:00:00Z,X-1"), [csvUrl("PyPI")]: csv() }) }, RUN);
    expect(await items("other")).toHaveLength(1);
  });
  it("refuses to run without a bootstrap", async () => {
    await env.DB.exec("DELETE FROM sync_state");
    await expect(planRun({ db: env.DB, fetch: router({}) }, RUN)).rejects.toBeInstanceOf(PlanError);
  });
  it("fails, retryably, when OSV is unavailable", async () => {
    const f = router({ [csvUrl("npm")]: new Response("", { status: 503 }) });
    await expect(planRun({ db: env.DB, fetch: f }, RUN)).rejects.toThrow(/HTTP 503/);
  });
  it("refuses a delta that is really a rebuild", async () => {
    const lines = Array.from({ length: MAX_DELTA + 1 }, (_, i) => `2026-11-06T00:00:00Z,GHSA-${i}`);
    await expect(planRun({ db: env.DB, fetch: router({ [csvUrl("npm")]: csv(...lines), [csvUrl("PyPI")]: csv() }) }, RUN)).rejects.toThrow(/run the bootstrap/);
  });
  it("applies the limit across both ecosystems together", async () => {
    const half = Array.from({ length: MAX_DELTA / 2 + 1 }, (_, i) => `2026-11-06T00:00:00Z,GHSA-${i}`);
    await expect(planRun({ db: env.DB, fetch: router({ [csvUrl("npm")]: csv(...half), [csvUrl("PyPI")]: csv(...half) }) }, RUN)).rejects.toThrow(/run the bootstrap/);
  });
});

describe("processBatch", () => {
  const routes = (n: number, over: Routes = {}): Routes => ({
    ...Object.fromEntries(Array.from({ length: n }, (_, i) => [recUrl("npm", `GHSA-b-${i}`), Response.json(rec(`GHSA-b-${i}`, "2026-11-06T00:00:00Z", `pkg-${i}`))])),
    ...over,
  });
  const plan = (n: number) => insertItems(Array.from({ length: n }, (_, i) => [i, "npm", `GHSA-b-${i}`, `2026-11-06T00:00:${String(i % 60).padStart(2, "0")}Z`]));
  const deps = (f: FetchLike) => ({ db: env.DB, kv: env.PKG_INDEX, fetch: f, now: NOW, sleep: async () => {} });

  it("fetches, applies to D1 and KV, and marks the items done", async () => {
    await plan(3);
    const r = await processBatch(deps(router(routes(3))), RUN, 0);
    expect(r).toEqual({ processed: 3, ok: 3, missing: 0, failed: 0, added: 3, updated: 0, withdrawn: 0 });
    expect((await items()).map((i) => i.status)).toEqual(["done", "done", "done"]);
    expect(await env.PKG_INDEX.get("npm:pkg-1", "json")).not.toBeNull();
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories").first<{ n: number }>())?.n).toBe(3);
  });
  it("processes only its own slice", async () => {
    await plan(BATCH_SIZE + 5);
    const first = await processBatch(deps(router(routes(BATCH_SIZE + 5))), RUN, 0);
    expect(first.processed).toBe(BATCH_SIZE);
    const rows = await items();
    expect(rows.filter((r) => r.status === "done")).toHaveLength(BATCH_SIZE);
    expect(rows.filter((r) => r.status === "pending")).toHaveLength(5);
    const second = await processBatch(deps(router(routes(BATCH_SIZE + 5))), RUN, BATCH_SIZE);
    expect(second.processed).toBe(5);
    expect((await items()).every((r) => r.status === "done")).toBe(true);
  });
  it("returns zeros for a slice beyond the list", async () => {
    await plan(2);
    expect(await processBatch(deps(router({})), RUN, 500)).toMatchObject({ processed: 0, ok: 0 });
  });
  it("marks a 404 missing and a bad fetch failed, and still applies the rest", async () => {
    await plan(4);
    const f = router(routes(4, { [recUrl("npm", "GHSA-b-1")]: new Response("", { status: 404 }), [recUrl("npm", "GHSA-b-2")]: new Response("", { status: 403 }) }));
    const r = await processBatch(deps(f), RUN, 0);
    expect(r).toMatchObject({ processed: 4, ok: 2, missing: 1, failed: 1, added: 2 });
    expect((await items()).map((i) => i.status)).toEqual(["done", "missing", "failed", "done"]);
    expect(await env.PKG_INDEX.get("npm:pkg-0", "json")).not.toBeNull();
    expect(await env.PKG_INDEX.get("npm:pkg-2", "json")).toBeNull();
  });
  it("leaves the items pending, so the step can be retried, when applying throws", async () => {
    await plan(2);
    const broken = { ...deps(router(routes(2))), db: new Proxy(env.DB, { get: (t, p) => (p === "batch" ? async () => { throw new Error("D1 down"); } : Reflect.get(t, p, t)) }) as D1Database };
    await expect(processBatch(broken, RUN, 0)).rejects.toThrow("D1 down");
    expect((await items()).every((i) => i.status === "pending")).toBe(true);
  });
  it("is idempotent across a retry", async () => {
    await plan(3);
    await processBatch(deps(router(routes(3))), RUN, 0);
    const again = await processBatch(deps(router(routes(3))), RUN, 0);
    expect(again).toMatchObject({ ok: 3, added: 0, updated: 3 });
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories").first<{ n: number }>())?.n).toBe(3);
  });
  it("fetches each item from its own ecosystem's directory", async () => {
    await insertItems([[0, "pypi", "PYSEC-1", "2026-11-06T00:00:00Z"]]);
    const calls: string[] = [];
    await processBatch(deps(router({ [recUrl("PyPI", "PYSEC-1")]: Response.json(rec("PYSEC-1", "2026-11-06T00:00:00Z", "somepkg", "PyPI")) }, calls)), RUN, 0);
    expect(calls).toEqual([recUrl("PyPI", "PYSEC-1")]);
    expect(await env.PKG_INDEX.get("pypi:somepkg", "json")).not.toBeNull();
  });
});

describe("advanceHighWater", () => {
  const run = async (rows: Array<[string, string, string, string]>, npm = "2026-11-01T00:00:00Z") => {
    await seedState(npm, "2026-11-01T00:00:00Z");
    await env.DB.prepare("DELETE FROM refresh_items WHERE run_id = ?").bind(RUN).run();
    await insertItems(rows.map(([eco, id, modified, status], i) => [i, eco, id, modified, status]));
    return advanceHighWater(env.DB, RUN, NOW);
  };

  it("advances to the newest settled record when everything succeeded", async () => {
    const r = await run([["npm", "A", "2026-11-06T01:00:00Z", "done"], ["npm", "B", "2026-11-06T09:00:00Z", "done"]]);
    expect(r).toEqual({ highWater: { npm: "2026-11-06T09:00:00Z" }, failed: 0 });
    expect((await state("npm"))?.last_modified).toBe("2026-11-06T09:00:00Z");
  });
  it("counts a missing record as settled", async () => {
    await run([["npm", "A", "2026-11-06T09:00:00Z", "missing"]]);
    expect((await state("npm"))?.last_modified).toBe("2026-11-06T09:00:00Z");
  });
  it("stops just before the oldest failure, so it is fetched again next time", async () => {
    const r = await run([["npm", "A", "2026-11-06T01:00:00Z", "done"], ["npm", "B", "2026-11-06T05:00:00Z", "failed"], ["npm", "C", "2026-11-06T09:00:00Z", "done"]]);
    expect(r).toEqual({ highWater: { npm: "2026-11-06T01:00:00Z" }, failed: 1 });
    expect((await state("npm"))?.last_modified).toBe("2026-11-06T01:00:00Z");
  });
  it("does not move at all when the oldest item failed", async () => {
    const r = await run([["npm", "A", "2026-11-06T01:00:00Z", "failed"], ["npm", "B", "2026-11-06T09:00:00Z", "done"]]);
    expect(r.highWater).toEqual({});
    expect((await state("npm"))?.last_modified).toBe("2026-11-01T00:00:00Z");
  });
  it("does not advance past a failure that shares a timestamp with a success", async () => {
    await run([["npm", "A", "2026-11-06T05:00:00Z", "done"], ["npm", "B", "2026-11-06T05:00:00Z", "failed"]]);
    expect((await state("npm"))?.last_modified).toBe("2026-11-01T00:00:00Z");
  });
  it("compares timestamps chronologically across mixed precision", async () => {
    // 04.4Z is later than 04Z, but sorts earlier as a string.
    await run([["npm", "A", "2026-11-06T11:30:04Z", "done"], ["npm", "B", "2026-11-06T11:30:04.4Z", "done"]]);
    expect((await state("npm"))?.last_modified).toBe("2026-11-06T11:30:04.4Z");
    await run([["npm", "A", "2026-11-06T11:30:04.4Z", "failed"], ["npm", "B", "2026-11-06T11:30:04Z", "done"]], "2026-11-01T00:00:00Z");
    expect((await state("npm"))?.last_modified).toBe("2026-11-06T11:30:04Z");
  });
  it("never moves the mark backwards", async () => {
    await run([["npm", "A", "2026-11-02T00:00:00Z", "done"]], "2026-11-05T00:00:00Z");
    expect((await state("npm"))?.last_modified).toBe("2026-11-05T00:00:00Z");
  });
  it("treats each ecosystem independently", async () => {
    const r = await run([["npm", "A", "2026-11-06T01:00:00Z", "failed"], ["pypi", "P", "2026-11-06T02:00:00Z", "done"]]);
    expect(r.highWater).toEqual({ pypi: "2026-11-06T02:00:00Z" });
    expect((await state("npm"))?.last_modified).toBe("2026-11-01T00:00:00Z");
    expect((await state("pypi"))?.last_modified).toBe("2026-11-06T02:00:00Z");
  });
  it("stamps last_synced_at even when nothing changed", async () => {
    const r = await run([]);
    expect(r).toEqual({ highWater: {}, failed: 0 });
    expect((await state("npm"))?.last_synced_at).toBe(NOW);
    expect((await state("pypi"))?.last_synced_at).toBe(NOW);
  });
  it("ignores pending items entirely", async () => {
    await run([["npm", "A", "2026-11-06T01:00:00Z", "pending"]]);
    expect((await state("npm"))?.last_modified).toBe("2026-11-01T00:00:00Z");
  });
});

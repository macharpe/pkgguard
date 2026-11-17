import { env } from "cloudflare:test";
import { NonRetryableError } from "cloudflare:workflows";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WorkflowStep } from "cloudflare:workers";
import { executeRefresh } from "../src/refresh/workflow.js";
import { OSV_BASE } from "../src/refresh/osv-fetch.js";
import { MAX_DELTA } from "../src/refresh/plan.js";
import { getRun } from "../src/refresh/runs.js";

const RUN = "11111111-1111-4111-8111-111111111111";
const pkg = (eco: string, name: string) => ({ package: { ecosystem: eco, name }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] });
const csvUrl = (dir: string) => `${OSV_BASE}/${dir}/modified_id.csv`;
const recUrl = (dir: string, id: string) => `${OSV_BASE}/${dir}/${id}.json`;
const stamp = (i: number) => `2026-11-06T${String(Math.floor(i / 3600)).padStart(2, "0")}:${String(Math.floor(i / 60) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z`;

interface StepCall {
  name: string;
  config: unknown;
}
function fakeStep() {
  const calls: StepCall[] = [];
  const step = {
    do: async (name: string, a: unknown, b?: unknown) => {
      calls.push({ name, config: typeof a === "function" ? undefined : a });
      return await ((typeof a === "function" ? a : b) as () => Promise<unknown>)();
    },
  } as unknown as WorkflowStep;
  return { step, calls };
}

type Handler = (url: string) => Response | undefined;
let handlers: Handler[] = [];
const stubFetch = (...hs: Handler[]) => {
  handlers = hs;
  vi.stubGlobal("fetch", async (url: string) => {
    for (const h of handlers) {
      const r = h(url);
      if (r) return r;
    }
    // The other ecosystems are enabled too: unless a test routes them, they have nothing new.
    if (["crates.io", "RubyGems", "NuGet", "Go"].some((dir) => url === csvUrl(dir))) return new Response("");
    return new Response("", { status: 404 });
  });
};
const csv = (dir: string, ids: string[], stamps: (i: number) => string = stamp) => (url: string) =>
  url === csvUrl(dir) ? new Response(ids.map((id, i) => `${stamps(i)},${id}`).reverse().join("\n") + "\n") : undefined;
const records = (dir: string, ids: string[], eco: string, bad: Record<string, number> = {}) => (url: string) => {
  const m = new RegExp(`^${OSV_BASE}/${dir}/(.+)\\.json$`).exec(url);
  if (!m) return undefined;
  const id = m[1] as string;
  if (bad[id]) return new Response("", { status: bad[id] });
  return Response.json({ id, modified: "2026-11-06T00:00:00Z", summary: "s", affected: [pkg(eco, id.toLowerCase())] });
};

const seedState = (npm = "2026-11-05T00:00:00Z") =>
  env.DB.batch([
    env.DB.prepare("DELETE FROM sync_state"),
    env.DB.prepare("INSERT INTO sync_state (ecosystem, last_modified, record_count, last_synced_at) VALUES ('npm', ?, 1, '2026-11-01T00:00:00Z'), ('pypi', '2026-11-05T00:00:00Z', 1, '2026-11-01T00:00:00Z'), ('cargo', '2026-11-05T00:00:00Z', 1, '2026-11-01T00:00:00Z'), ('rubygems', '2026-11-05T00:00:00Z', 1, '2026-11-01T00:00:00Z'), ('nuget', '2026-11-05T00:00:00Z', 1, '2026-11-01T00:00:00Z'), ('go', '2026-11-05T00:00:00Z', 1, '2026-11-01T00:00:00Z')").bind(npm),
  ]);
const startRow = () => env.DB.prepare("INSERT INTO refresh_runs (id, kind, trigger, status, started_at) VALUES (?, 'manual', 'test', 'queued', ?)").bind(RUN, new Date().toISOString()).run();
const drive = async (e: Parameters<typeof executeRefresh>[0] = env) => {
  const { step, calls } = fakeStep();
  const outcome = await executeRefresh(e, RUN, step).then((v) => ({ ok: true as const, v }), (err: unknown) => ({ ok: false as const, e: err }));
  return { outcome, calls };
};
const itemCount = async () => (await env.DB.prepare("SELECT COUNT(*) AS n FROM refresh_items WHERE run_id = ?").bind(RUN).first<{ n: number }>())?.n;
const state = (eco: string) => env.DB.prepare("SELECT last_modified, record_count, last_synced_at FROM sync_state WHERE ecosystem = ?").bind(eco).first<{ last_modified: string; record_count: number; last_synced_at: string }>();

beforeEach(async () => {
  await env.DB.batch([env.DB.prepare("DELETE FROM refresh_items"), env.DB.prepare("DELETE FROM advisories"), env.DB.prepare("DELETE FROM refresh_runs")]);
  const kv = await env.PKG_INDEX.list();
  await Promise.all(kv.keys.map((k) => env.PKG_INDEX.delete(k.name)));
  await seedState();
  await startRow();
});
afterEach(() => vi.unstubAllGlobals());

describe("RefreshWorkflow", () => {
  it("runs a full delta: plan, one step per batch, finalize; and leaves D1, KV and sync state correct", async () => {
    const ids = Array.from({ length: 250 }, (_, i) => `GHSA-w-${String(i).padStart(4, "0")}`);
    stubFetch(csv("npm", ids), csv("PyPI", []), records("npm", ids, "npm"));
    const { outcome, calls } = await drive();

    expect(outcome).toMatchObject({ ok: true, v: { total: 250, added: 250, updated: 0, failed: 0 } });
    expect(calls.map((c) => c.name)).toEqual(["start", "plan", "records 0-99", "records 100-199", "records 200-249", "finalize", "notify"]);

    expect(await getRun(env.DB, RUN)).toMatchObject({ status: "complete", phase: "complete", items_total: 250, items_done: 250, added: 250, errors: 0, error_detail: null });
    expect((await getRun(env.DB, RUN))?.finished_at).not.toBeNull();
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories").first<{ n: number }>())?.n).toBe(250);
    expect(await env.PKG_INDEX.get("npm:ghsa-w-0007", "json")).not.toBeNull();
    expect((await state("npm"))?.last_modified).toBe(stamp(249));
    expect((await state("npm"))?.record_count).toBe(250);
    expect(await itemCount()).toBe(0); // a clean run leaves no work list behind
  });

  it("reports progress after every batch, not only at the end: this is what the progress bar reads", async () => {
    const ids = Array.from({ length: 250 }, (_, i) => `GHSA-p-${String(i).padStart(4, "0")}`);
    stubFetch(csv("npm", ids), csv("PyPI", []), records("npm", ids, "npm"));
    const seen: Array<{ after: string; done: number; total: number; phase: string | null; status: string }> = [];
    const step = {
      do: async (name: string, a: unknown, b?: unknown) => {
        const out = await ((typeof a === "function" ? a : b) as () => Promise<unknown>)();
        const run = await getRun(env.DB, RUN);
        seen.push({ after: name, done: run?.items_done ?? -1, total: run?.items_total ?? -1, phase: run?.phase ?? null, status: run?.status ?? "" });
        return out;
      },
    } as unknown as WorkflowStep;
    await executeRefresh(env, RUN, step);
    const byStep = Object.fromEntries(seen.map((x) => [x.after, x]));
    expect(byStep["plan"]).toMatchObject({ done: 0, total: 250, status: "running", phase: "fetching records" });
    expect(byStep["records 0-99"]).toMatchObject({ done: 100, total: 250, phase: "applying records" });
    expect(byStep["records 100-199"]).toMatchObject({ done: 200, total: 250 });
    expect(byStep["records 200-249"]).toMatchObject({ done: 250, total: 250 });
    expect(byStep["finalize"]).toMatchObject({ status: "complete", phase: "complete" });
  });

  it("counts withdrawn records as removed", async () => {
    const ids = ["GHSA-x-0001", "GHSA-x-0002", "GHSA-x-0003"];
    stubFetch(csv("npm", ids), csv("PyPI", []), (url) => {
      const m = /\/npm\/(.+)\.json$/.exec(url);
      if (!m) return undefined;
      const id = m[1] as string;
      return Response.json({ id, modified: "2026-11-06T00:00:00Z", affected: [pkg("npm", id.toLowerCase())], ...(id === "GHSA-x-0001" || id === "GHSA-x-0003" ? { withdrawn: "2026-11-06T00:00:00Z" } : {}) });
    });
    const { outcome } = await drive();
    expect(outcome).toMatchObject({ ok: true, v: { withdrawn: 2 } });
    expect(await getRun(env.DB, RUN)).toMatchObject({ removed: 2, added: 3 });
  });

  it("configures retries on the network-bound steps", async () => {
    stubFetch(csv("npm", ["GHSA-r-0001"]), csv("PyPI", []), records("npm", ["GHSA-r-0001"], "npm"));
    const { calls } = await drive();
    for (const name of ["plan", "records 0-0"]) {
      expect(calls.find((c) => c.name === name)?.config, name).toMatchObject({ retries: { limit: 3, backoff: "exponential" } });
    }
  });

  it("finishes cleanly with no batch steps when nothing changed", async () => {
    stubFetch(csv("npm", [], stamp), csv("PyPI", []));
    const { outcome, calls } = await drive();
    expect(outcome).toMatchObject({ ok: true, v: { total: 0, added: 0, failed: 0 } });
    expect(calls.map((c) => c.name)).toEqual(["start", "plan", "finalize", "notify"]);
    expect(await getRun(env.DB, RUN)).toMatchObject({ status: "complete", items_total: 0 });
    expect((await state("npm"))?.last_synced_at).not.toBe("2026-11-01T00:00:00Z");
  });

  it("completes with errors, keeps the work list and holds the high-water mark back when records fail", async () => {
    const ids = ["GHSA-e-0001", "GHSA-e-0002", "GHSA-e-0003", "GHSA-e-0004"];
    stubFetch(csv("npm", ids), csv("PyPI", []), records("npm", ids, "npm", { "GHSA-e-0003": 403 }));
    const { outcome } = await drive();

    expect(outcome).toMatchObject({ ok: true, v: { total: 4, added: 3, failed: 1 } });
    expect(await getRun(env.DB, RUN)).toMatchObject({ status: "complete", errors: 1, items_done: 4 });
    expect((await getRun(env.DB, RUN))?.error_detail).toMatch(/1 records could not be fetched/);
    expect(await itemCount()).toBe(4);
    expect((await state("npm"))?.last_modified).toBe(stamp(1)); // just before the failed record at index 2
  });

  it("marks the run failed and stops, with no retry, when there is no bootstrap", async () => {
    await env.DB.exec("DELETE FROM sync_state");
    stubFetch(csv("npm", []));
    const { outcome, calls } = await drive();
    expect(outcome.ok).toBe(false);
    expect((outcome as { e: unknown }).e).toBeInstanceOf(NonRetryableError);
    expect(calls.map((c) => c.name)).toEqual(["start", "plan", "record failure", "notify failure"]);
    expect(await getRun(env.DB, RUN)).toMatchObject({ status: "failed", phase: "failed" });
    expect((await getRun(env.DB, RUN))?.error_detail).toMatch(/run the bootstrap first/);
  });

  it("refuses a delta that is really a rebuild, without retrying", async () => {
    const ids = Array.from({ length: MAX_DELTA + 1 }, (_, i) => `GHSA-big-${i}`);
    stubFetch(csv("npm", ids, () => "2026-11-06T00:00:00Z"), csv("PyPI", []));
    const { outcome } = await drive();
    expect((outcome as { e: unknown }).e).toBeInstanceOf(NonRetryableError);
    expect((await getRun(env.DB, RUN))?.error_detail).toMatch(/run the bootstrap/);
  });

  it("fails the run, retryably, when OSV is down", async () => {
    stubFetch((u) => (u === csvUrl("npm") ? new Response("", { status: 503 }) : undefined));
    const { outcome } = await drive();
    expect(outcome.ok).toBe(false);
    expect((outcome as { e: unknown }).e).not.toBeInstanceOf(NonRetryableError);
    expect((await getRun(env.DB, RUN))?.error_detail).toMatch(/HTTP 503/);
    expect((await state("npm"))?.last_modified).toBe("2026-11-05T00:00:00Z");
  });

  it("fails the run when a batch cannot be applied, leaving the items pending and the mark where it was", async () => {
    const ids = ["GHSA-d-0001", "GHSA-d-0002"];
    stubFetch(csv("npm", ids), csv("PyPI", []), records("npm", ids, "npm"));
    const realBatch = env.DB.batch.bind(env.DB);
    const broken = new Proxy(env.DB, {
      get: (t, p) =>
        p === "batch"
          ? async (statements: D1PreparedStatement[]) => {
              // Fail only the advisory write; the bookkeeping writes around it still work.
              if (statements.some((s) => (s as unknown as { statement?: string }).statement?.includes("DELETE FROM advisories"))) throw new Error("D1 down");
              return realBatch(statements);
            }
          : Reflect.get(t, p, t),
    }) as D1Database;
    const { outcome } = await drive({ ...env, DB: broken });
    expect(outcome.ok).toBe(false);
    expect(String((outcome as { e: unknown }).e)).toContain("D1 down");
    expect(await getRun(env.DB, RUN)).toMatchObject({ status: "failed" });
    expect((await state("npm"))?.last_modified).toBe("2026-11-05T00:00:00Z");
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM refresh_items WHERE run_id = ? AND status = 'pending'").bind(RUN).first<{ n: number }>())?.n).toBe(2);
  });

  it("truncates a long failure message to 500 characters", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("x".repeat(2000));
    });
    await drive();
    const detail = (await getRun(env.DB, RUN))?.error_detail ?? "";
    expect(detail).toHaveLength(500);
    expect(detail).toMatch(/^x+$/);
  });

  it("records both a monthly-sized and a repeat run idempotently: a second run over the same data adds nothing", async () => {
    const ids = ["GHSA-i-0001", "GHSA-i-0002"];
    stubFetch(csv("npm", ids), csv("PyPI", []), records("npm", ids, "npm"));
    await drive();
    const kvBefore = await env.PKG_INDEX.get("npm:ghsa-i-0001");
    await env.DB.prepare("UPDATE sync_state SET last_modified = '2026-11-05T00:00:00Z' WHERE ecosystem = 'npm'").run();
    await env.DB.prepare("DELETE FROM refresh_runs").run();
    await startRow();
    const { outcome } = await drive();
    expect(outcome).toMatchObject({ ok: true, v: { added: 0, updated: 2 } });
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM advisories").first<{ n: number }>())?.n).toBe(2);
    expect((JSON.parse((await env.PKG_INDEX.get("npm:ghsa-i-0001")) ?? "{}") as { m: unknown }).m).toEqual((JSON.parse(kvBefore ?? "{}") as { m: unknown }).m);
  });
});

import { env } from "cloudflare:test";
import type { WorkflowStep } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { notifyRefresh } from "../src/refresh/notify.js";
import { executeRefresh } from "../src/refresh/workflow.js";
import { OSV_BASE } from "../src/refresh/osv-fetch.js";

const HOOK = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=K&token=T";
const RUN = "22222222-2222-4222-8222-222222222222";
const withHook = (over: Record<string, unknown> = {}) => ({ ...env, GCHAT_WEBHOOK: HOOK, PUBLIC_URL: "https://pkgguard.example.com", ...over });

interface Posted { url: string; text: string }
function chat(status = 200) {
  const posted: Posted[] = [];
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("https://chat.googleapis.com/")) {
      posted.push({ url, text: (JSON.parse(String(init?.body)) as { text: string }).text });
      return new Response("{}", { status });
    }
    return new Response("", { status: 404 });
  });
  return { posted, spy };
}
const seedRun = (over: Record<string, unknown> = {}) => {
  const r = { status: "complete", kind: "daily", trigger: "cron", added: 19, updated: 6, removed: 0, errors: 0, error_detail: null, items_total: 25, started_at: "2026-11-07T04:00:00Z", finished_at: "2026-11-07T04:00:07Z", ...over };
  return env.DB.prepare("INSERT INTO refresh_runs (id, kind, trigger, status, items_total, added, updated, removed, errors, error_detail, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .bind(RUN, r.kind, r.trigger, r.status, r.items_total, r.added, r.updated, r.removed, r.errors, r.error_detail, r.started_at, r.finished_at).run();
};
beforeEach(async () => {
  await env.DB.batch([env.DB.prepare("DELETE FROM refresh_runs"), env.DB.prepare("DELETE FROM refresh_items"), env.DB.prepare("DELETE FROM advisories")]);
});
afterEach(() => vi.restoreAllMocks());

describe("notifyRefresh", () => {
  it("reports a completed run that changed something, with its numbers and a link", async () => {
    await seedRun();
    const { posted } = chat();
    expect(await notifyRefresh(withHook(), RUN)).toBe("sent");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.text).toContain("✅");
    expect(posted[0]?.text).toContain("19 added, 6 updated (25 records in 7s)");
    expect(posted[0]?.text).toContain("daily run, started by `cron`");
    expect(posted[0]?.text).toContain("<https://pkgguard.example.com|Open the dashboard>");
  });
  it("stays quiet about a run that changed nothing: a quiet day is not news", async () => {
    await seedRun({ added: 0, updated: 12 });
    const { posted } = chat();
    expect(await notifyRefresh(withHook(), RUN)).toBe("not-needed");
    expect(posted).toEqual([]);
  });
  it("reports a run that added nothing but left records to retry", async () => {
    await seedRun({ added: 0, errors: 3 });
    const { posted } = chat();
    expect(await notifyRefresh(withHook(), RUN)).toBe("sent");
    expect(posted[0]?.text).toContain("3 records could not be fetched");
  });
  it("always reports a failure, with the reason", async () => {
    await seedRun({ status: "failed", added: 0, error_detail: "no sync state for npm: run the bootstrap first" });
    const { posted } = chat();
    expect(await notifyRefresh(withHook(), RUN)).toBe("sent");
    expect(posted[0]?.text).toContain("❌");
    expect(posted[0]?.text).toContain("no sync state for npm");
  });
  it.each(["queued", "running"])("says nothing about a %s run", async (status) => {
    await seedRun({ status });
    const { posted } = chat();
    expect(await notifyRefresh(withHook(), RUN)).toBe("not-needed");
    expect(posted).toEqual([]);
  });
  it("is skipped, without touching the network, when no webhook is configured", async () => {
    await seedRun();
    const { spy } = chat();
    expect(await notifyRefresh({ ...withHook(), GCHAT_WEBHOOK: undefined }, RUN)).toBe("skipped");
    expect(spy).not.toHaveBeenCalled();
  });
  it("is skipped for a run that does not exist", async () => {
    const { posted } = chat();
    expect(await notifyRefresh(withHook(), RUN)).toBe("skipped");
    expect(posted).toEqual([]);
  });
  it("never throws: a Chat failure or a broken database becomes a result", async () => {
    await seedRun();
    chat(500);
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await notifyRefresh(withHook(), RUN)).toBe("failed");
    const broken = withHook({ DB: { prepare: () => { throw new Error("D1 down"); } } });
    expect(await notifyRefresh(broken as never, RUN)).toBe("failed");
  });
  it("leaves out the link when the dashboard address is not https", async () => {
    await seedRun();
    const { posted } = chat();
    await notifyRefresh(withHook({ PUBLIC_URL: "http://insecure.example.com" }), RUN);
    expect(posted[0]?.text).not.toContain("Open the dashboard");
  });
  it("shows no duration when the run has not finished", async () => {
    await seedRun({ finished_at: null });
    const { posted } = chat();
    await notifyRefresh(withHook(), RUN);
    expect(posted[0]?.text).toContain("(25 records)");
  });
});

describe("notifications inside a refresh run", () => {
  const pkg = (name: string) => ({ package: { ecosystem: "npm", name }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] });
  const stepper = () => {
    const names: string[] = [];
    const step = { do: async (name: string, a: unknown, b?: unknown) => (names.push(name), await ((typeof a === "function" ? a : b) as () => Promise<unknown>)()) } as unknown as WorkflowStep;
    return { step, names };
  };
  const osv = (ids: string[], failChat = false, posted: Posted[] = []) => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url.startsWith("https://chat.googleapis.com/")) {
        posted.push({ url, text: (JSON.parse(String(init?.body)) as { text: string }).text });
        return new Response("{}", { status: failChat ? 500 : 200 });
      }
      if (url === `${OSV_BASE}/npm/modified_id.csv`) return new Response(ids.map((id, i) => `2026-11-06T00:00:${String(i).padStart(2, "0")}Z,${id}`).join("\n") + "\n");
      if (url === `${OSV_BASE}/PyPI/modified_id.csv`) return new Response("");
      if (url === `${OSV_BASE}/crates.io/modified_id.csv`) return new Response("");
      if (url === `${OSV_BASE}/RubyGems/modified_id.csv`) return new Response("");
      if (url === `${OSV_BASE}/NuGet/modified_id.csv`) return new Response("");
      if (url === `${OSV_BASE}/Go/modified_id.csv`) return new Response("");
      const m = /\/npm\/(.+)\.json$/.exec(url);
      return m ? Response.json({ id: m[1], modified: "2026-11-06T00:00:00Z", affected: [pkg(String(m[1]).toLowerCase())] }) : new Response("", { status: 404 });
    });
    return posted;
  };
  const seedState = () => env.DB.batch([env.DB.prepare("DELETE FROM sync_state"), env.DB.prepare("INSERT INTO sync_state VALUES ('npm','2026-11-05T00:00:00Z',1,'x'),('pypi','2026-11-05T00:00:00Z',1,'x'),('cargo','2026-11-05T00:00:00Z',1,'x'),('rubygems','2026-11-05T00:00:00Z',1,'x'),('nuget','2026-11-05T00:00:00Z',1,'x'),('go','2026-11-05T00:00:00Z',1,'x')")]);
  const startRow = () => env.DB.prepare("INSERT INTO refresh_runs (id, kind, trigger, status, started_at) VALUES (?, 'daily', 'cron', 'queued', '2026-11-07T00:00:00Z')").bind(RUN).run();

  beforeEach(async () => {
    await seedState();
    await startRow();
  });

  it("announces a run that added records, as its own step after finalize", async () => {
    const posted = osv(["GHSA-n-0001", "GHSA-n-0002"]);
    const { step, names } = stepper();
    await executeRefresh(withHook(), RUN, step);
    expect(names.at(-2)).toBe("finalize");
    expect(names.at(-1)).toBe("notify");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.text).toContain("2 added, 0 updated");
  });
  it("does not announce a run with nothing new", async () => {
    const posted = osv([]);
    await executeRefresh(withHook(), RUN, stepper().step);
    expect(posted).toEqual([]);
  });
  it("announces a failed run, once, and still raises the original error", async () => {
    await env.DB.exec("DELETE FROM sync_state");
    const posted = osv([]);
    const { step, names } = stepper();
    await expect(executeRefresh(withHook(), RUN, step)).rejects.toThrow(/run the bootstrap first/);
    expect(names.slice(-2)).toEqual(["record failure", "notify failure"]);
    expect(posted).toHaveLength(1);
    expect(posted[0]?.text).toContain("❌");
  });
  it("completes normally, with correct data, when Chat is down", async () => {
    const posted = osv(["GHSA-c-0001"], true);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const result = await executeRefresh(withHook(), RUN, stepper().step);
    expect(result).toMatchObject({ total: 1, added: 1, failed: 0 });
    expect((await env.DB.prepare("SELECT status FROM refresh_runs WHERE id = ?").bind(RUN).first<{ status: string }>())?.status).toBe("complete");
    expect(posted).toHaveLength(1);
  });
  it("reports the original failure, not a Chat problem, when both go wrong", async () => {
    await env.DB.exec("DELETE FROM sync_state");
    osv([], true);
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(executeRefresh(withHook(), RUN, stepper().step)).rejects.toThrow(/run the bootstrap first/);
  });
  it("sends nothing without a webhook", async () => {
    const posted = osv(["GHSA-w-0001"]);
    await executeRefresh({ ...withHook(), GCHAT_WEBHOOK: undefined }, RUN, stepper().step);
    expect(posted).toEqual([]);
  });
});

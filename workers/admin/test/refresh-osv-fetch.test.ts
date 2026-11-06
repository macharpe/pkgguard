import { describe, expect, it } from "vitest";
import { OSV_BASE, fetchRecord, fetchRecords, type FetchLike } from "../src/refresh/osv-fetch.js";

const rec = (id: string, extra: Record<string, unknown> = {}) => ({ id, modified: "2026-11-06T00:00:00Z", ...extra });
const noSleep = async () => {};
const ok = (body: unknown): Response => Response.json(body);

describe("fetchRecord", () => {
  it("builds the per-ecosystem URL and returns a validated record", async () => {
    const seen: string[] = [];
    const f: FetchLike = async (url) => (seen.push(url), ok(rec("GHSA-1")));
    expect(await fetchRecord(f, "npm", "GHSA-1", { sleep: noSleep })).toMatchObject({ status: "ok" });
    await fetchRecord(f, "pypi", "GHSA-1", { sleep: noSleep });
    expect(seen).toEqual([`${OSV_BASE}/npm/GHSA-1.json`, `${OSV_BASE}/PyPI/GHSA-1.json`]);
  });
  it("reports 404 as missing, without retrying", async () => {
    let calls = 0;
    const f: FetchLike = async () => (calls++, new Response("", { status: 404 }));
    expect(await fetchRecord(f, "npm", "X-1", { sleep: noSleep })).toEqual({ status: "missing" });
    expect(calls).toBe(1);
  });
  it.each([500, 503, 429])("retries HTTP %d and succeeds when it recovers", async (status) => {
    let calls = 0;
    const f: FetchLike = async () => (++calls < 3 ? new Response("", { status }) : ok(rec("X-1")));
    expect(await fetchRecord(f, "npm", "X-1", { sleep: noSleep })).toMatchObject({ status: "ok" });
    expect(calls).toBe(3);
  });
  it("gives up after the configured attempts and says why", async () => {
    let calls = 0;
    const f: FetchLike = async () => (calls++, new Response("", { status: 503 }));
    expect(await fetchRecord(f, "npm", "X-1", { sleep: noSleep, attempts: 3 })).toEqual({ status: "failed", reason: "HTTP 503" });
    expect(calls).toBe(3);
  });
  it("does not retry a non-retryable client error", async () => {
    let calls = 0;
    const f: FetchLike = async () => (calls++, new Response("", { status: 403 }));
    expect(await fetchRecord(f, "npm", "X-1", { sleep: noSleep })).toEqual({ status: "failed", reason: "HTTP 403" });
    expect(calls).toBe(1);
  });
  it("retries a network error, then fails", async () => {
    let calls = 0;
    const f: FetchLike = async () => {
      calls++;
      throw new TypeError("boom");
    };
    expect(await fetchRecord(f, "npm", "X-1", { sleep: noSleep })).toEqual({ status: "failed", reason: "network error" });
    expect(calls).toBe(3);
  });
  it("backs off exponentially between attempts", async () => {
    const delays: number[] = [];
    await fetchRecord(async () => new Response("", { status: 500 }), "npm", "X-1", { attempts: 4, sleep: async (ms) => void delays.push(ms) });
    expect(delays).toEqual([250, 500, 1000]);
  });
  it("rejects a record whose id does not match the one requested, so a swapped file cannot poison the index", async () => {
    expect(await fetchRecord(async () => ok(rec("SOMETHING-ELSE")), "npm", "X-1", { sleep: noSleep })).toEqual({ status: "failed", reason: "unexpected record" });
  });
  it.each([[{ id: "X-1" }], [null], [[]], ["string"], [{ id: "X-1", modified: 5 }]])("rejects malformed record %j", async (body) => {
    expect((await fetchRecord(async () => ok(body), "npm", "X-1", { sleep: noSleep })).status).toBe("failed");
  });
  it("rejects a non-JSON body without retrying it", async () => {
    let calls = 0;
    const f: FetchLike = async () => (calls++, new Response("<html>", { status: 200 }));
    expect(await fetchRecord(f, "npm", "X-1", { sleep: noSleep })).toEqual({ status: "failed", reason: "not JSON" });
    expect(calls).toBe(1);
  });
  it.each(["../x", "a/b", "a b", "", "x".repeat(129), "a?b", "a#b"])("refuses to build a URL from unsafe id %j", async (id) => {
    let calls = 0;
    expect(await fetchRecord(async () => (calls++, ok({})), "npm", id, { sleep: noSleep })).toEqual({ status: "failed", reason: "unsafe id" });
    expect(calls).toBe(0);
  });
});

describe("fetchRecords", () => {
  const items = (n: number) => Array.from({ length: n }, (_, i) => ({ ecosystem: "npm" as const, id: `GHSA-${i}` }));

  it("returns results in input order regardless of completion order", async () => {
    const f: FetchLike = async (url) => {
      const id = /\/(GHSA-\d+)\.json/.exec(url)?.[1] as string;
      await new Promise((r) => setTimeout(r, id === "GHSA-0" ? 30 : 0));
      return ok(rec(id));
    };
    const results = await fetchRecords(f, items(5), { sleep: noSleep });
    expect(results.map((r) => (r.status === "ok" ? r.record.id : r.status))).toEqual(["GHSA-0", "GHSA-1", "GHSA-2", "GHSA-3", "GHSA-4"]);
  });
  it("never exceeds the concurrency limit", async () => {
    let active = 0;
    let peak = 0;
    const f: FetchLike = async (url) => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active--;
      return ok(rec(/\/(GHSA-\d+)\.json/.exec(url)?.[1] as string));
    };
    await fetchRecords(f, items(30), { concurrency: 6, sleep: noSleep });
    expect(peak).toBeLessThanOrEqual(6);
    expect(peak).toBeGreaterThan(1);
  });
  it("isolates failures: one bad record does not lose the others", async () => {
    const f: FetchLike = async (url) => {
      const id = /\/(GHSA-\d+)\.json/.exec(url)?.[1] as string;
      return id === "GHSA-1" ? new Response("", { status: 404 }) : id === "GHSA-2" ? new Response("", { status: 403 }) : ok(rec(id));
    };
    const results = await fetchRecords(f, items(4), { sleep: noSleep });
    expect(results.map((r) => r.status)).toEqual(["ok", "missing", "failed", "ok"]);
  });
  it("handles an empty list", async () => {
    expect(await fetchRecords(async () => ok({}), [], {})).toEqual([]);
  });
});

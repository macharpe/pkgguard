import { env } from "cloudflare:test";
import { buildKvEntry, distill, kvKey, type OsvRecord } from "@pkgguard/core";
import { beforeEach, describe, expect, it } from "vitest";
import eventStream from "../../../packages/core/test/fixtures/GHSA-mh6f-8j2x-4483.json";
import lodash from "../../../packages/core/test/fixtures/GHSA-35jh-r3h4-6jhm.json";
import solana from "../../../packages/core/test/fixtures/MAL-2024-11183.json";
import { applyRecords } from "../src/refresh/apply.js";

const NOW = "2026-11-07T00:00:00Z";
const deps = () => ({ db: env.DB, kv: env.PKG_INDEX, now: NOW });
const apply = (...records: unknown[]) => applyRecords(deps(), records as OsvRecord[]);
const rec = (over: Record<string, unknown>) => ({ id: "GHSA-test-0001", modified: "2026-11-06T00:00:00Z", summary: "s", affected: [], ...over });
const pkg = (ecosystem: string, name: string, extra: Record<string, unknown> = {}) => ({
  package: { ecosystem, name },
  ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
  ...extra,
});

const kvGet = async (key: string) => env.PKG_INDEX.get(key, "json") as Promise<{ m: Array<{ id: string }>; c: Array<{ id: string }>; u: string } | null>;
const rows = async (osvId?: string) =>
  (await env.DB.prepare(`SELECT ecosystem, osv_id, package_name, kind, withdrawn FROM advisories ${osvId ? "WHERE osv_id = ?" : ""} ORDER BY ecosystem, osv_id, package_name`).bind(...(osvId ? [osvId] : [])).all<{ ecosystem: string; osv_id: string; package_name: string; kind: string; withdrawn: number }>()).results;
const clear = async () => {
  await env.DB.exec("DELETE FROM advisories");
  const list = await env.PKG_INDEX.list();
  await Promise.all(list.keys.map((k) => env.PKG_INDEX.delete(k.name)));
};
beforeEach(clear);

describe("applyRecords: a new record", () => {
  it("writes its rows to D1 and a KV entry identical to the bootstrap's", async () => {
    const result = await apply(eventStream);
    expect(result).toMatchObject({ added: 1, updated: 0, withdrawn: 0, packages: 2, kvWrites: 2, kvDeletes: 0, unreadableRows: 0 });
    expect((await rows()).map((r) => r.package_name)).toEqual(["event-stream", "flatmap-stream"]);

    // The same distill + buildKvEntry path the offline bootstrap uses.
    const expected = buildKvEntry(distill(eventStream as unknown as OsvRecord).filter((r) => r.packageName === "event-stream"), NOW);
    expect(await kvGet(kvKey("npm", "event-stream") as string)).toEqual(expected);
  });
  it("is idempotent: applying again changes nothing and counts it as an update", async () => {
    await apply(eventStream, lodash);
    const d1 = await rows();
    const kv = await kvGet("npm:lodash");
    const again = await apply(eventStream, lodash);
    expect(again).toMatchObject({ added: 0, updated: 2 });
    expect(await rows()).toEqual(d1);
    expect(await kvGet("npm:lodash")).toEqual(kv);
  });
  it("counts added and updated separately in one batch", async () => {
    await apply(eventStream);
    expect(await apply(eventStream, solana)).toMatchObject({ added: 1, updated: 1 });
  });
  it("does nothing for an empty batch", async () => {
    expect(await apply()).toMatchObject({ added: 0, updated: 0, packages: 0 });
    expect(await rows()).toEqual([]);
  });
});

describe("applyRecords: KV is rebuilt from D1, not from the batch", () => {
  it("merges advisories that arrive in different batches for the same package", async () => {
    await apply(rec({ id: "GHSA-aaaa-0001", affected: [pkg("npm", "shared")] }));
    await apply(rec({ id: "GHSA-bbbb-0002", affected: [pkg("npm", "shared")] }));
    expect((await kvGet("npm:shared"))?.c.map((a) => a.id).sort()).toEqual(["GHSA-aaaa-0001", "GHSA-bbbb-0002"]);
  });
  it("merges two records for one package inside a single batch", async () => {
    await apply(rec({ id: "GHSA-aaaa-0001", affected: [pkg("npm", "shared")] }), rec({ id: "GHSA-bbbb-0002", affected: [pkg("npm", "shared")] }));
    expect((await kvGet("npm:shared"))?.c).toHaveLength(2);
  });
  it("separates malware from vulnerabilities in the entry", async () => {
    await apply(rec({ id: "MAL-2026-1", affected: [pkg("npm", "mixed", { ranges: undefined })] }), rec({ id: "GHSA-x-1", affected: [pkg("npm", "mixed")] }));
    const entry = await kvGet("npm:mixed");
    expect(entry?.m.map((a) => a.id)).toEqual(["MAL-2026-1"]);
    expect(entry?.c.map((a) => a.id)).toEqual(["GHSA-x-1"]);
  });
});

describe("applyRecords: a record that changes", () => {
  it("drops the stale advisory when OSV stops listing a package, and deletes its KV entry", async () => {
    const r = rec({ id: "GHSA-chg-0001", affected: [pkg("npm", "keeps"), pkg("npm", "dropped")] });
    await apply(r);
    expect(await kvGet("npm:dropped")).not.toBeNull();
    const result = await apply({ ...r, modified: "2026-11-07T00:00:00Z", affected: [pkg("npm", "keeps")] });
    expect((await rows("GHSA-chg-0001")).map((x) => x.package_name)).toEqual(["keeps"]);
    expect(await kvGet("npm:dropped")).toBeNull();
    expect(await kvGet("npm:keeps")).not.toBeNull();
    expect(result.kvDeletes).toBe(1);
  });
  it("replaces ranges in place", async () => {
    const r = rec({ id: "GHSA-rng-0001", affected: [pkg("npm", "ranged")] });
    await apply(r);
    await apply({ ...r, affected: [{ package: { ecosystem: "npm", name: "ranged" }, ranges: [{ type: "SEMVER", events: [{ introduced: "5.0.0" }, { fixed: "6.0.0" }] }] }] });
    const entry = await kvGet("npm:ranged");
    expect(JSON.stringify(entry)).toContain("5.0.0");
    expect(JSON.stringify(entry)).not.toContain('"fixed":"2.0.0"');
  });
  it("keeps the other record's advisory when one record for a shared package is withdrawn", async () => {
    await apply(rec({ id: "GHSA-aaaa-0001", affected: [pkg("npm", "shared")] }), rec({ id: "GHSA-bbbb-0002", affected: [pkg("npm", "shared")] }));
    const result = await apply(rec({ id: "GHSA-aaaa-0001", withdrawn: "2026-11-07T00:00:00Z", affected: [pkg("npm", "shared")] }));
    expect(result.withdrawn).toBe(1);
    expect((await kvGet("npm:shared"))?.c.map((a) => a.id)).toEqual(["GHSA-bbbb-0002"]);
    expect((await rows("GHSA-aaaa-0001"))[0]?.withdrawn).toBe(1);
  });
  it("deletes the KV entry when the last advisory for a package is withdrawn, but keeps the audit row", async () => {
    await apply(rec({ id: "GHSA-only-0001", affected: [pkg("npm", "solo")] }));
    await apply(rec({ id: "GHSA-only-0001", withdrawn: "2026-11-07T00:00:00Z", affected: [pkg("npm", "solo")] }));
    expect(await kvGet("npm:solo")).toBeNull();
    expect(await rows("GHSA-only-0001")).toHaveLength(1);
  });
  it("clears the rows and KV when a record no longer affects any package in scope", async () => {
    const r = rec({ id: "GHSA-gone-0001", affected: [pkg("npm", "was-here")] });
    await apply(r);
    await apply({ ...r, affected: [pkg("Maven", "a:b")] });
    expect(await rows("GHSA-gone-0001")).toEqual([]);
    expect(await kvGet("npm:was-here")).toBeNull();
  });
});

describe("applyRecords: ecosystems and names", () => {
  it("indexes PyPI under its PEP 503 normalised key", async () => {
    await apply(rec({ id: "PYSEC-1", affected: [pkg("PyPI", "Typing_Extensions")] }));
    expect(await kvGet("pypi:typing-extensions")).not.toBeNull();
    expect((await rows("PYSEC-1"))[0]?.package_name).toBe("typing-extensions");
  });
  it("lowercases npm names and keeps the scope", async () => {
    await apply(rec({ id: "GHSA-s-1", affected: [pkg("npm", "@Scope/Name")] }));
    expect(await kvGet("npm:@scope/name")).not.toBeNull();
  });
  it("ignores ecosystems out of scope", async () => {
    const result = await apply(rec({ id: "GHSA-out-1", affected: [pkg("Maven", "a:b"), pkg("Packagist", "vendor/pkg"), pkg("Hex", "plug")] }));
    expect(result.packages).toBe(0);
    expect(await rows()).toEqual([]);
    expect((await env.PKG_INDEX.list()).keys).toEqual([]);
  });
  it("a record can span both in-scope ecosystems", async () => {
    await apply(rec({ id: "GHSA-both-1", affected: [pkg("npm", "dual"), pkg("PyPI", "dual")] }));
    expect(await kvGet("npm:dual")).not.toBeNull();
    expect(await kvGet("pypi:dual")).not.toBeNull();
  });
  it("skips a name too long for a KV key rather than failing the batch", async () => {
    const long = "a".repeat(600);
    const result = await apply(rec({ id: "GHSA-long-1", affected: [pkg("npm", long), pkg("npm", "fine")] }));
    expect(await kvGet("npm:fine")).not.toBeNull();
    expect((await env.PKG_INDEX.list()).keys.map((k) => k.name)).toEqual(["npm:fine"]);
    expect(result.kvWrites).toBe(1);
  });
});

describe("applyRecords: scale and resilience", () => {
  it("handles a batch larger than the 100-parameter cap per query", async () => {
    const records = Array.from({ length: 250 }, (_, i) => rec({ id: `GHSA-bulk-${String(i).padStart(4, "0")}`, affected: [pkg("npm", `bulk-${i}`)] }));
    const result = await apply(...records);
    expect(result).toMatchObject({ added: 250, updated: 0, packages: 250, kvWrites: 250 });
    expect(await rows()).toHaveLength(250);
    expect((await env.PKG_INDEX.list({ prefix: "npm:bulk-" })).keys.length).toBe(250);
    expect(await apply(...records)).toMatchObject({ added: 0, updated: 250 });
  });
  it("many records touching one package are rebuilt once from D1", async () => {
    const records = Array.from({ length: 120 }, (_, i) => rec({ id: `GHSA-hot-${String(i).padStart(4, "0")}`, affected: [pkg("npm", "hot")] }));
    const result = await apply(...records);
    expect(result.packages).toBe(1);
    expect((await kvGet("npm:hot"))?.c).toHaveLength(120);
  });
  it("leaves an unreadable D1 row out of the entry and reports it, instead of failing the rebuild", async () => {
    await apply(rec({ id: "GHSA-ok-0001", affected: [pkg("npm", "damaged")] }));
    await env.DB.prepare("INSERT INTO advisories (ecosystem, osv_id, package_name, kind, ranges_json, withdrawn, modified) VALUES ('npm','GHSA-bad-0001','damaged','vulnerability','{not json',0,'2026-11-06T00:00:00Z')").run();
    const result = await apply(rec({ id: "GHSA-new-0002", affected: [pkg("npm", "damaged")] }));
    expect(result.unreadableRows).toBe(1);
    expect((await kvGet("npm:damaged"))?.c.map((a) => a.id).sort()).toEqual(["GHSA-new-0002", "GHSA-ok-0001"]);
  });
  it("stamps the entry with the run's time", async () => {
    await apply(rec({ id: "GHSA-ts-0001", affected: [pkg("npm", "stamped")] }));
    expect((await kvGet("npm:stamped"))?.u).toBe(NOW);
  });
  it("replaces a negative-cache marker the filter left under the same key", async () => {
    await env.PKG_INDEX.put("npm:newly-bad", JSON.stringify({ v: 1, n: true, u: "2026-11-06T00:00:00Z" }));
    await apply(rec({ id: "MAL-2026-9", affected: [pkg("npm", "newly-bad", { ranges: undefined })] }));
    const entry = await kvGet("npm:newly-bad");
    expect(entry?.m.map((a) => a.id)).toEqual(["MAL-2026-9"]);
    expect(JSON.stringify(entry)).not.toContain('"n":true');
  });
});

describe("applyRecords: atomicity", () => {
  it("does not leave a record half-applied if the D1 write fails", async () => {
    const r = rec({ id: "GHSA-atom-0001", affected: [pkg("npm", "atomic")] });
    await apply(r);
    const failing = { ...deps(), db: new Proxy(env.DB, { get: (t, p, rcv) => (p === "batch" ? async () => { throw new Error("D1 down"); } : Reflect.get(t, p, t)) }) as D1Database };
    await expect(applyRecords(failing, [{ ...r, affected: [pkg("npm", "atomic"), pkg("npm", "extra")] } as unknown as OsvRecord])).rejects.toThrow("D1 down");
    expect((await rows("GHSA-atom-0001")).map((x) => x.package_name)).toEqual(["atomic"]);
    expect(await kvGet("npm:extra")).toBeNull();
  });
});

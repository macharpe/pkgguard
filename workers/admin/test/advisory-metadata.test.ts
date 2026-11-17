import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AdvisoriesResponse, DetectionsResponse } from "../src/api-types.js";
import { METADATA_SQL } from "../src/api/advisory-metadata.js";
import { adminEnv, addAdvisory, addDetection, call, setup, user } from "./harness.js";

beforeEach(setup);
const rating = { score: 9.8, version: "3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source: "OSV severity" };
const get = async (query = ""): Promise<DetectionsResponse> => (await call(`/api/detections${query}`, await user())).json();
const unknown = (osv_id: string, status: "withdrawn" | "not-indexed") => ({ osv_id, status, kind: null, severity: null, cvss: null });

describe("current advisory metadata", () => {
  it("enriches only recorded matching IDs, scoped by ecosystem and exact package name", async () => {
    await addAdvisory({ ecosystem: "npm", name: "one", id: "V1", kind: "vulnerability", severity: "HIGH", cvss: rating });
    await addAdvisory({ ecosystem: "npm", name: "one", id: "OTHER-VERSION", kind: "vulnerability", severity: "CRITICAL" });
    await addAdvisory({ ecosystem: "pypi", name: "one", id: "V1", kind: "malware" });
    await addAdvisory({ ecosystem: "npm", name: "other", id: "V1", kind: "malware" });
    await addDetection({ package_name: "one", verdict: "flagged", reason: "osv-cve", osv_ids: "V1,V1,MISSING" });
    expect((await get()).items[0]?.advisories).toEqual([
      { osv_id: "V1", status: "current", kind: "vulnerability", severity: "HIGH", cvss: rating },
      unknown("MISSING", "not-indexed"),
    ]);
  });

  it("tells a withdrawn advisory from one that was never indexed, and drops the withdrawn one's severity", async () => {
    await addAdvisory({ ecosystem: "npm", name: "one", id: "GONE", kind: "malware", severity: "CRITICAL", cvss: rating, withdrawn: 1 });
    await addDetection({ package_name: "one", osv_ids: "GONE,LIVE-ONLY" });
    expect((await get()).items[0]?.advisories).toEqual([unknown("GONE", "withdrawn"), unknown("LIVE-ONLY", "not-indexed")]);
  });

  it("shows the current classification beside a decision that recorded another reason", async () => {
    await addAdvisory({ ecosystem: "npm", name: "one", id: "RECLASSIFIED", kind: "vulnerability", severity: "LOW" });
    await addDetection({ package_name: "one", verdict: "blocked", reason: "osv-malware", osv_ids: "RECLASSIFIED" });
    const row = (await get()).items[0];
    expect(row?.reason).toBe("osv-malware");
    expect(row?.advisories?.[0]).toMatchObject({ status: "current", kind: "vulnerability" });
  });

  it("does not invent findings for overrides or clean downloads", async () => {
    await addDetection({ reason: "override", verdict: "blocked" });
    await addDetection({});
    expect((await get()).items.map((row) => row.advisories)).toEqual([[], []]);
  });

  it("uses current metadata without changing verdicts or the pagination cursor", async () => {
    await addAdvisory({ ecosystem: "npm", name: "one", id: "V1", kind: "vulnerability", severity: "LOW" });
    for (let i = 0; i < 3; i++) await addDetection({ package_name: "one", verdict: "flagged", osv_ids: "V1" });
    const first = await get("?limit=2");
    expect(first.items.map((row) => row.verdict)).toEqual(["flagged", "flagged"]);
    expect(first.items[0]?.advisories?.[0]?.severity).toBe("LOW");
    await env.DB.prepare("UPDATE advisories SET severity = 'CRITICAL'").run();
    const second = await get(`?limit=2&before=${first.nextBefore}`);
    expect(second.items).toHaveLength(1);
    expect(second.items[0]?.advisories?.[0]?.severity).toBe("CRITICAL");
    expect(second.items[0]?.verdict).toBe("flagged");
    expect(second.nextBefore).toBeNull();
  });

  it("enriches every ID on a full page of rows that each carry many IDs", async () => {
    const perRow = 40;
    const rows = 200;
    const statements = [];
    for (let r = 0; r < rows; r++) {
      const ids = Array.from({ length: perRow }, (_, i) => `V${r}-${i}`);
      statements.push(env.DB.prepare("INSERT INTO detections (ts,ecosystem,package_name,version,verdict,osv_ids) VALUES ('2026-11-01','npm',?,'1.0.0','flagged',?)").bind(`pkg-${r}`, ids.join(",")));
      for (const id of ids) {
        statements.push(env.DB.prepare("INSERT INTO advisories (ecosystem, osv_id, package_name, kind, severity, ranges_json, withdrawn, modified) VALUES ('npm',?,?,'vulnerability','HIGH','{\"r\":[],\"v\":[]}',0,'2026-11-01')").bind(id, `pkg-${r}`));
      }
    }
    for (let i = 0; i < statements.length; i += 500) await env.DB.batch(statements.slice(i, i + 500));
    const result = await get("?limit=200");
    expect(result.items).toHaveLength(rows);
    expect(result.items.every((row) => row.advisories?.length === perRow && row.advisories.every((a) => a.status === "current"))).toBe(true);
  }, 60_000);

  it("keeps the feed working, without the metadata, when the lookup fails", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    await addDetection({ package_name: "one", verdict: "flagged", osv_ids: "V1" });
    const real = env.DB;
    const failing = { ...real, prepare: (sql: string) => (sql.includes("json_each") ? ({ bind: () => { throw new Error("d1 exploded"); } } as never) : real.prepare(sql)), batch: real.batch.bind(real) } as unknown as D1Database;
    const response = await call("/api/detections", await user(), {}, adminEnv({ DB: failing }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as DetectionsResponse;
    expect(body.items).toHaveLength(1);
    expect(body.items[0]?.advisories).toBeUndefined();
    expect(spy).toHaveBeenCalledWith("detection advisory metadata unavailable", "d1 exploded");
    spy.mockRestore();
  });

  it("joins through the advisories primary key rather than scanning the table", async () => {
    const plan = await env.DB.prepare(`EXPLAIN QUERY PLAN ${METADATA_SQL}`).bind("[]").all<{ detail: string }>();
    const details = plan.results.map((r) => r.detail).join("\n");
    expect(details).not.toMatch(/SCAN advisories/);
    expect(details).toMatch(/SEARCH a USING/);
    expect(details).toMatch(/ecosystem=\? AND osv_id=\? AND package_name=\?/);
  });

  it("validates stored CVSS metadata and exposes it consistently in package lookup, never leaking the raw column", async () => {
    await addAdvisory({ ecosystem: "npm", name: "one", id: "V1", kind: "vulnerability", cvss: rating });
    await addAdvisory({ ecosystem: "npm", name: "one", id: "V2", kind: "vulnerability", cvss: { ...rating, score: 50 } });
    await addAdvisory({ ecosystem: "npm", name: "one", id: "V3", kind: "vulnerability" });
    await env.DB.prepare("UPDATE advisories SET cvss_json = 'not json' WHERE osv_id = 'V3'").run();
    const response = await call("/api/advisories?q=one&ecosystem=npm", await user());
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toContain("cvss_json");
    const result = JSON.parse(text) as AdvisoriesResponse;
    expect(result.items[0]?.vulnerabilities.map((row) => row.cvss)).toEqual([rating, null, null]);
  });
});

import { env } from "cloudflare:test";
import { ECOSYSTEMS, ENABLED_ECOSYSTEMS, type OsvRecord } from "@pkgguard/core";
import { beforeEach, describe, expect, it } from "vitest";
import { applyRecords } from "../src/refresh/apply.js";
import { OSV_BASE, fetchRecord, type FetchLike } from "../src/refresh/osv-fetch.js";
import { parseOverrideInput } from "../src/overrides.js";
import { planRun } from "../src/refresh/plan.js";
import { call, setup, user } from "./harness.js";

/**
 * The admin Worker must treat every enabled ecosystem alike. Each scenario runs once per enabled ecosystem, so
 * enabling a new one that a call site (an `IN (...)` clause, a directory name, an enumeration) forgot fails here.
 */
const NOW = "2026-11-07T00:00:00Z";
const pkg = (osvName: string, name: string) => ({
  package: { ecosystem: osvName, name },
  ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
});
const rec = (id: string, osvName: string, ...names: string[]) =>
  ({ id, modified: "2026-11-06T00:00:00Z", summary: "s", affected: names.map((n) => pkg(osvName, n)) }) as unknown as OsvRecord;

const rows = async (id: string) =>
  (await env.DB.prepare("SELECT osv_id, package_name FROM advisories WHERE ecosystem = ? ORDER BY package_name").bind(id).all<{ osv_id: string; package_name: string }>()).results.map(
    (r) => `${r.osv_id}:${r.package_name}`,
  );

beforeEach(async () => {
  await setup();
  await env.DB.batch([env.DB.prepare("DELETE FROM advisories"), env.DB.prepare("DELETE FROM sync_state"), env.DB.prepare("DELETE FROM refresh_items")]);
  const kv = await env.PKG_INDEX.list();
  await Promise.all(kv.keys.map((k) => env.PKG_INDEX.delete(k.name)));
});

describe.each(ENABLED_ECOSYSTEMS)("enabled ecosystem %s", (id) => {
  const spec = ECOSYSTEMS[id];

  it("loses a package's rows and KV entry when its record stops listing it", async () => {
    const deps = { db: env.DB, kv: env.PKG_INDEX, now: NOW };
    await applyRecords(deps, [rec("GHSA-wire-0001", spec.osvName, "alpha", "beta")]);
    expect(await rows(id)).toEqual(["GHSA-wire-0001:alpha", "GHSA-wire-0001:beta"]);
    expect(await env.PKG_INDEX.get(`${id}:alpha`)).not.toBeNull();
    expect(await env.PKG_INDEX.get(`${id}:beta`)).not.toBeNull();

    await applyRecords(deps, [rec("GHSA-wire-0001", spec.osvName, "alpha")]);
    expect(await rows(id)).toEqual(["GHSA-wire-0001:alpha"]);
    expect(await env.PKG_INDEX.get(`${id}:beta`), "the dropped package's KV entry is gone").toBeNull();
    expect(await env.PKG_INDEX.get(`${id}:alpha`)).not.toBeNull();
  });

  it("is fetched from the directory OSV calls it", async () => {
    const seen: string[] = [];
    const fetchFn: FetchLike = async (url) => (seen.push(url), Response.json({ id: "X-1", modified: "2026-11-06T00:00:00Z" }));
    expect(await fetchRecord(fetchFn, id, "X-1", { sleep: async () => {} })).toMatchObject({ status: "ok" });
    expect(seen).toEqual([`${OSV_BASE}/${spec.osvName}/X-1.json`]);
  });

  it("has its change list requested by refresh planning", async () => {
    await env.DB.batch(
      ENABLED_ECOSYSTEMS.map((e) =>
        env.DB.prepare("INSERT INTO sync_state (ecosystem, last_modified, record_count, last_synced_at) VALUES (?, '2026-11-05T00:00:00Z', 1, '2026-11-05T00:00:00Z')").bind(e),
      ),
    );
    const requested: string[] = [];
    const fetchFn: FetchLike = async (url) => (requested.push(url), new Response(`2026-11-06T00:00:00Z,GHSA-${url.split("/").at(-2)}-1\n`));
    const { total } = await planRun({ db: env.DB, fetch: fetchFn }, "run-wire");
    expect(total).toBe(ENABLED_ECOSYSTEMS.length);
    expect(requested).toContain(`${OSV_BASE}/${spec.osvName}/modified_id.csv`);
    const planned = await env.DB.prepare("SELECT ecosystem FROM refresh_items WHERE run_id = 'run-wire'").all<{ ecosystem: string }>();
    expect(planned.results.map((r) => r.ecosystem)).toContain(id);
  });

  it("is accepted as an override target, with the guards every ecosystem shares", () => {
    expect(parseOverrideInput({ ecosystem: id, mode: "block", name: "ab" })).toMatchObject({ ecosystem: id, name: "ab" });
    // ".." is not here: PyPI folds a run of separators to "-", which its pattern accepts (the stored key is "-", so it
    // is harmless). npm rejects it, and overrides.test.ts covers that.
    for (const name of ["", "a b", "a//b", "/x"]) {
      expect(() => parseOverrideInput({ ecosystem: id, mode: "block", name }), JSON.stringify(name)).toThrow();
    }
  });

  it("can be asked for by the detections and advisories filters", async () => {
    const token = await user();
    expect((await call(`/api/detections?ecosystem=${id}`, token)).status).toBe(200);
    expect((await call(`/api/advisories?q=ab&ecosystem=${id}`, token)).status).toBe(200);
  });
});

describe("the API's ecosystem filters", () => {
  it("name every enabled ecosystem when refusing one", async () => {
    const token = await user();
    for (const path of ["/api/detections?ecosystem=nope", "/api/advisories?q=ab&ecosystem=nope"]) {
      const response = await call(path, token);
      expect(response.status, path).toBe(400);
      expect(((await response.json()) as { error: string }).error, path).toContain(ENABLED_ECOSYSTEMS.join(", "));
    }
  });

  it("search every enabled ecosystem when none is named", async () => {
    await env.DB.batch(
      ENABLED_ECOSYSTEMS.map((e) =>
        env.DB.prepare(
          "INSERT INTO advisories (ecosystem, osv_id, package_name, namespace, kind, cwe_ids, severity, summary, ranges_json, withdrawn, modified) VALUES (?, ?, 'shared-name', NULL, 'malware', NULL, NULL, 's', '{\"r\":[],\"v\":[\"1.0.0\"]}', 0, '2026-11-06T00:00:00Z')",
        ).bind(e, `MAL-${e}-1`),
      ),
    );
    const body = (await (await call("/api/advisories?q=shared-name", await user())).json()) as { items: Array<{ ecosystem: string }> };
    expect(body.items.map((i) => i.ecosystem).sort()).toEqual([...ENABLED_ECOSYSTEMS].sort());
  });
});

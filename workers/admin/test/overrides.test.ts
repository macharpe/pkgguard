import { env } from "cloudflare:test";
import { overrideApplies, overrideKey, parseOverride, parsePackageUrl } from "@pkgguard/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { decide } from "../../filter/src/decide.js";
import { CSRF_HEADER } from "../src/index.js";
import { HttpError } from "../src/http.js";
import { MAX_OVERRIDES, deleteOverride, listOverrides, parseOverrideInput, parseOverrideRef, putOverride } from "../src/overrides.js";
import { call, serviceToken, setup, user } from "./harness.js";

const HOOK = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=K&token=T";
const NOW = new Date("2026-11-07T10:00:00Z");
const base = { ecosystem: "npm", name: "left-pad", mode: "block" };
const clear = async () => {
  await env.DB.exec("DELETE FROM overrides");
  const list = await env.PKG_INDEX.list({ prefix: "override:" });
  await Promise.all(list.keys.map((k) => env.PKG_INDEX.delete(k.name)));
};
beforeEach(async () => {
  await setup();
  await clear();
});
afterEach(() => vi.restoreAllMocks());

const bad = (body: Record<string, unknown>, message: RegExp) => {
  try {
    parseOverrideInput(body);
  } catch (e) {
    expect(e).toBeInstanceOf(HttpError);
    expect((e as HttpError).status).toBe(400);
    expect((e as HttpError).message).toMatch(message);
    return;
  }
  throw new Error("expected a rejection");
};

describe("parseOverrideInput", () => {
  it("accepts the minimum and defaults to every version with no note", () => {
    expect(parseOverrideInput(base)).toEqual({ ecosystem: "npm", name: "left-pad", mode: "block", versions: null, note: null });
  });
  it("normalises the name exactly as the filter will look it up", () => {
    expect(parseOverrideInput({ ...base, name: "  @Scope/Name  " }).name).toBe("@scope/name");
    expect(parseOverrideInput({ ecosystem: "pypi", mode: "allow", name: "Typing_Extensions" }).name).toBe("typing-extensions");
    expect(parseOverrideInput({ ecosystem: "pypi", mode: "allow", name: "A.B__c" }).name).toBe("a-b-c");
  });
  it("trims, de-duplicates and keeps the order of versions", () => {
    expect(parseOverrideInput({ ...base, versions: [" 1.0.0 ", "2.0.0", "1.0.0"] }).versions).toEqual(["1.0.0", "2.0.0"]);
  });
  it("treats an explicit null versions the same as omitted", () => {
    expect(parseOverrideInput({ ...base, versions: null }).versions).toBeNull();
  });
  it("accepts real version syntax: semver prerelease and build, PEP 440 epoch and local", () => {
    expect(parseOverrideInput({ ...base, versions: ["1.0.0-rc.1+build.5", "1!2.0.post1+local.1", "2.0.0~dev"] }).versions).toHaveLength(3);
  });
  it("neutralises control characters in the note and drops an empty one", () => {
    expect(parseOverrideInput({ ...base, note: "line1\nline2\u0000x" }).note).toBe("line1 line2 x");
    expect(parseOverrideInput({ ...base, note: "   " }).note).toBeNull();
  });
  it.each([
    [{ ...base, ecosystem: "gem" }, /ecosystem/],
    [{ ...base, ecosystem: undefined }, /ecosystem/],
    [{ ...base, mode: "deny" }, /mode/],
    [{ ...base, mode: undefined }, /mode/],
    [{ ...base, name: undefined }, /name is required/],
    [{ ...base, name: 5 }, /name is required/],
    [{ ...base, name: "" }, /1 to 214/],
    [{ ...base, name: "   " }, /1 to 214/],
    [{ ...base, name: "a".repeat(215) }, /1 to 214/],
    [{ ...base, name: "has space" }, /characters/],
    [{ ...base, name: "a;DROP TABLE overrides" }, /characters/],
    [{ ...base, name: "a<b>" }, /characters/],
    [{ ...base, name: "../etc/passwd" }, /characters/],
    [{ ...base, name: "/leading" }, /characters/],
    [{ ...base, name: "a//b" }, /characters/],
    [{ ...base, name: "@scope/" }, /characters/],
    [{ ...base, name: "@a/b/c" }, /characters/],
    [{ ecosystem: "pypi", mode: "block", name: "has/slash" }, /characters/],
    [{ ...base, versions: [] }, /must not be empty/],
    [{ ...base, versions: "1.0.0" }, /must be a list/],
    [{ ...base, versions: [1] }, /characters a version/],
    [{ ...base, versions: [""] }, /characters a version/],
    [{ ...base, versions: ["1 0"] }, /characters a version/],
    [{ ...base, versions: ["<1.0"] }, /characters a version/],
    [{ ...base, versions: ["1".repeat(129)] }, /characters a version/],
    [{ ...base, versions: Array.from({ length: 101 }, (_, i) => `1.0.${i}`) }, /at most 100/],
    [{ ...base, note: 5 }, /note must be text/],
    [{ ...base, note: "x".repeat(501) }, /at most 500/],
  ] as Array<[Record<string, unknown>, RegExp]>)("rejects %j", (body, message) => bad(body, message));

  it("parseOverrideRef needs only ecosystem, mode and name", () => {
    expect(parseOverrideRef({ ecosystem: "npm", mode: "allow", name: "X" })).toEqual({ ecosystem: "npm", mode: "allow", name: "x" });
    expect(() => parseOverrideRef({ ecosystem: "npm", mode: "allow" })).toThrow(HttpError);
  });
});

describe("putOverride / deleteOverride", () => {
  const input = (over: Record<string, unknown> = {}) => parseOverrideInput({ ...base, ...over });
  const kv = async (key: string) => env.PKG_INDEX.get(key, "json");
  const rowCount = async () => (await env.DB.prepare("SELECT COUNT(*) AS n FROM overrides").first<{ n: number }>())?.n;

  it("writes D1 and the KV entry the filter reads", async () => {
    const { created, row } = await putOverride(env, input({ note: "emergency" }), "ops@example.com", NOW);
    expect(created).toBe(true);
    expect(row).toMatchObject({ package_name: "left-pad", mode: "block", versions: null, note: "emergency", created_by: "ops@example.com", created_at: NOW.toISOString() });
    expect(await kv("override:block:npm:left-pad")).toEqual({ v: 1, versions: null, note: "emergency" });
    expect(await listOverrides(env.DB)).toEqual([row]);
  });
  it("replaces in place and reports it was not new", async () => {
    await putOverride(env, input(), "a@example.com", NOW);
    const second = await putOverride(env, input({ versions: ["1.0.0"], note: "narrowed" }), "b@example.com", new Date(NOW.getTime() + 1000));
    expect(second.created).toBe(false);
    expect(await rowCount()).toBe(1);
    expect(await kv("override:block:npm:left-pad")).toEqual({ v: 1, versions: ["1.0.0"], note: "narrowed" });
    expect((await listOverrides(env.DB))[0]).toMatchObject({ versions: ["1.0.0"], created_by: "b@example.com" });
  });
  it("omits the note from KV when there is none", async () => {
    await putOverride(env, input(), "a@example.com", NOW);
    expect(await kv("override:block:npm:left-pad")).toEqual({ v: 1, versions: null });
  });
  it("keeps a block and an allow for the same package side by side", async () => {
    await putOverride(env, input({ mode: "block" }), "a", NOW);
    await putOverride(env, input({ mode: "allow", versions: ["1.0.0"] }), "a", NOW);
    expect(await rowCount()).toBe(2);
    expect(await kv("override:block:npm:left-pad")).not.toBeNull();
    expect(await kv("override:allow:npm:left-pad")).not.toBeNull();
  });
  it("lists newest first", async () => {
    await putOverride(env, input({ name: "a-first" }), "a", new Date("2026-11-01T00:00:00Z"));
    await putOverride(env, input({ name: "b-second" }), "a", new Date("2026-11-03T00:00:00Z"));
    expect((await listOverrides(env.DB)).map((r) => r.package_name)).toEqual(["b-second", "a-first"]);
  });

  it("writes KV in a form the filter's own parser and matcher understand", async () => {
    await putOverride(env, input({ name: "all-versions" }), "a", NOW);
    await putOverride(env, input({ name: "some-versions", versions: ["1.0.0", "1.0.1"] }), "a", NOW);
    const all = parseOverride(await kv(overrideKey("block", "npm", "all-versions") as string));
    const some = parseOverride(await kv(overrideKey("block", "npm", "some-versions") as string));
    expect(all && overrideApplies("npm", all, "9.9.9")).toBe(true);
    expect(some && overrideApplies("npm", some, "1.0.1")).toBe(true);
    expect(some && overrideApplies("npm", some, "2.0.0")).toBe(false);
  });

  it("undoes a new override in D1 when the KV write fails, so the dashboard never shows one the filter lacks", async () => {
    const broken = { ...env, PKG_INDEX: { put: async () => { throw new Error("KV down"); } } as unknown as KVNamespace };
    await expect(putOverride(broken, input(), "a", NOW)).rejects.toThrow("KV down");
    expect(await rowCount()).toBe(0);
  });
  it("puts the previous override back when replacing fails at KV", async () => {
    await putOverride(env, input({ note: "original" }), "a@example.com", NOW);
    const broken = { ...env, PKG_INDEX: { put: async () => { throw new Error("KV down"); } } as unknown as KVNamespace };
    await expect(putOverride(broken, input({ note: "replacement" }), "b@example.com", NOW)).rejects.toThrow("KV down");
    expect((await listOverrides(env.DB))[0]).toMatchObject({ note: "original", created_by: "a@example.com" });
    expect(await kv("override:block:npm:left-pad")).toEqual({ v: 1, versions: null, note: "original" });
  });
  it(`refuses a new override past ${MAX_OVERRIDES}, but still allows replacing one`, async () => {
    await env.DB.batch(Array.from({ length: MAX_OVERRIDES }, (_, i) => env.DB.prepare("INSERT INTO overrides (ecosystem, package_name, mode, created_by, created_at) VALUES ('npm', ?, 'block', 'x', 'y')").bind(`pkg-${i}`)));
    await expect(putOverride(env, input({ name: "one-too-many" }), "a", NOW)).rejects.toMatchObject({ status: 409 });
    await expect(putOverride(env, input({ name: "pkg-5" }), "a", NOW)).resolves.toMatchObject({ created: false });
  });

  it("deletes from D1 and KV and returns what was removed", async () => {
    await putOverride(env, input({ versions: ["1.0.0"], note: "n" }), "a", NOW);
    const removed = await deleteOverride(env, { ecosystem: "npm", name: "left-pad", mode: "block" });
    expect(removed).toMatchObject({ package_name: "left-pad", versions: ["1.0.0"], note: "n" });
    expect(await rowCount()).toBe(0);
    expect(await kv("override:block:npm:left-pad")).toBeNull();
  });
  it("deletes only the named mode", async () => {
    await putOverride(env, input({ mode: "block" }), "a", NOW);
    await putOverride(env, input({ mode: "allow" }), "a", NOW);
    await deleteOverride(env, { ecosystem: "npm", name: "left-pad", mode: "block" });
    expect(await kv("override:allow:npm:left-pad")).not.toBeNull();
    expect(await rowCount()).toBe(1);
  });
  it("returns null for an unknown override but still clears a stray KV copy that the dashboard does not show", async () => {
    await env.PKG_INDEX.put("override:block:npm:stray", JSON.stringify({ v: 1, versions: null }));
    expect(await deleteOverride(env, { ecosystem: "npm", name: "stray", mode: "block" })).toBeNull();
    expect(await kv("override:block:npm:stray")).toBeNull();
  });
  it("restores the D1 row when the KV delete fails, so a block is never silently dropped from the list while still enforced", async () => {
    await putOverride(env, input({ note: "keep me" }), "a@example.com", NOW);
    const broken = { ...env, PKG_INDEX: { delete: async () => { throw new Error("KV down"); } } as unknown as KVNamespace };
    await expect(deleteOverride(broken, { ecosystem: "npm", name: "left-pad", mode: "block" })).rejects.toThrow("KV down");
    expect((await listOverrides(env.DB))[0]).toMatchObject({ package_name: "left-pad", note: "keep me", created_by: "a@example.com" });
    expect(await kv("override:block:npm:left-pad")).not.toBeNull();
  });
});

describe("the filter honours what the admin API writes", () => {
  const api = (method: "POST" | "DELETE", body: unknown, token?: Promise<string>) =>
    (async () => call(method === "POST" ? "/api/overrides" : "/api/overrides/remove", await (token ?? user()), { method: "POST", headers: { [CSRF_HEADER]: "1", "content-type": "application/json" }, body: JSON.stringify(body) }))();
  const decideFor = (url: string) => {
    const pkg = parsePackageUrl(url);
    if (!pkg) throw new Error("not a package url");
    return decide(pkg, { kv: env.PKG_INDEX, fetch: async () => new Response("{}"), osvTimeoutMs: 0, now: () => "2026-11-07T00:00:00Z" });
  };
  const tarball = (name: string, version: string) => `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`;

  it("blocks a package an administrator put on the block list, and stops when it is removed", async () => {
    expect(await decideFor(tarball("left-pad", "1.3.0"))).toMatchObject({ block: false });
    expect((await api("POST", { ...base, versions: ["1.3.0"] })).status).toBe(201);
    expect(await decideFor(tarball("left-pad", "1.3.0"))).toMatchObject({ block: true, reason: "override", source: "override" });
    expect(await decideFor(tarball("left-pad", "1.2.0"))).toMatchObject({ block: false });
    expect((await api("DELETE", base)).status).toBe(200);
    expect(await decideFor(tarball("left-pad", "1.3.0"))).toMatchObject({ block: false });
  });
  it("lets an allow override win over a block override for the same package", async () => {
    await api("POST", { ...base, mode: "block" });
    await api("POST", { ...base, mode: "allow", versions: ["1.3.0"] });
    expect(await decideFor(tarball("left-pad", "1.3.0"))).toMatchObject({ block: false, reason: "override" });
    expect(await decideFor(tarball("left-pad", "1.2.0"))).toMatchObject({ block: true });
  });
  it("finds a package whatever the case of the name it was entered with", async () => {
    await api("POST", { ...base, name: "Left-Pad" });
    expect(await decideFor(tarball("left-pad", "1.0.0"))).toMatchObject({ block: true });
  });
  it("covers a service-token write too", async () => {
    expect((await api("POST", base, serviceToken())).status).toBe(201);
    expect(await decideFor(tarball("left-pad", "1.0.0"))).toMatchObject({ block: true });
  });
});

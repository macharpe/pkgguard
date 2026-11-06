import { env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CSRF_HEADER } from "../src/index.js";
import { MAX_BODY_BYTES } from "../src/http.js";
import { adminEnv, call, serviceToken, setup, user } from "./harness.js";

const HOOK = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=K&token=T";
const JSON_CSRF = { [CSRF_HEADER]: "1", "content-type": "application/json" };
const base = { ecosystem: "npm", name: "left-pad", mode: "block" };
const body = async (r: Response) => (await r.json()) as any;

const post = async (payload: unknown, headers: Record<string, string> = JSON_CSRF, token: string | null | undefined = undefined, e = adminEnv()) =>
  call("/api/overrides", token === undefined ? await user() : token, { method: "POST", headers, body: typeof payload === "string" ? payload : JSON.stringify(payload) }, e);
const del = async (payload: unknown, headers: Record<string, string> = JSON_CSRF, token: string | null | undefined = undefined, e = adminEnv()) =>
  call("/api/overrides", token === undefined ? await user() : token, { method: "DELETE", headers, body: JSON.stringify(payload) }, e);

interface Posted { url: string; text: string }
function chat(status = 200) {
  const posted: Posted[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("https://chat.googleapis.com/")) {
      posted.push({ url, text: (JSON.parse(String(init?.body)) as { text: string }).text });
      return new Response("{}", { status });
    }
    return new Response("{}");
  });
  return posted;
}
const audits = async () => (await env.DB.prepare("SELECT actor, action, detail FROM audit_log ORDER BY id").all<{ actor: string; action: string; detail: string }>()).results;

beforeEach(async () => {
  await setup();
  await env.DB.exec("DELETE FROM overrides");
  const list = await env.PKG_INDEX.list({ prefix: "override:" });
  await Promise.all(list.keys.map((k) => env.PKG_INDEX.delete(k.name)));
});
afterEach(() => vi.restoreAllMocks());

describe("GET /api/overrides", () => {
  it("is empty to start with", async () => {
    expect(await body(await call("/api/overrides", await user()))).toEqual({ items: [] });
  });
  it("lists what was added, and needs authentication", async () => {
    await post({ ...base, versions: ["1.0.0"], note: "n" });
    const r = await body(await call("/api/overrides", await user()));
    expect(r.items).toEqual([expect.objectContaining({ ecosystem: "npm", package_name: "left-pad", mode: "block", versions: ["1.0.0"], note: "n", created_by: "demo@example.com" })]);
    expect((await call("/api/overrides", null)).status).toBe(401);
  });
});

describe("POST /api/overrides", () => {
  it("creates an override: 201, the stored item, a KV entry, and an audit record", async () => {
    const r = await post({ ...base, note: "emergency" });
    expect(r.status).toBe(201);
    expect(await body(r)).toMatchObject({ created: true, item: { package_name: "left-pad", mode: "block", versions: null, note: "emergency", created_by: "demo@example.com" } });
    expect(await env.PKG_INDEX.get("override:block:npm:left-pad", "json")).toEqual({ v: 1, versions: null, note: "emergency" });
    expect(await audits()).toEqual([{ actor: "demo@example.com", action: "override.add", detail: "block:npm:left-pad" }]);
  });
  it("replaces an existing one with 200 and records it as a replacement", async () => {
    await post(base);
    const r = await post({ ...base, versions: ["2.0.0"] });
    expect(r.status).toBe(200);
    expect((await body(r)).created).toBe(false);
    expect((await audits()).map((a) => a.action)).toEqual(["override.add", "override.replace"]);
  });
  it("records a service token as the actor", async () => {
    expect((await post(base, JSON_CSRF, await serviceToken())).status).toBe(201);
    expect((await audits())[0]?.actor).toBe("service-token:tok123.access");
  });
  it("is refused without authentication, before anything about the request is examined", async () => {
    expect((await post(base, JSON_CSRF, null)).status).toBe(401);
    expect((await post("not json at all", {}, null)).status).toBe(401);
  });
  it("is refused without the CSRF header, so another origin cannot add an allow-list entry", async () => {
    const r = await post(base, { "content-type": "application/json" });
    expect(r.status).toBe(403);
    expect((await body(r)).error).toBe("missing CSRF header");
    expect(await env.PKG_INDEX.get("override:block:npm:left-pad")).toBeNull();
  });
  it("requires a JSON content type: a plain HTML form cannot send one cross-origin without a preflight", async () => {
    for (const type of ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"]) {
      expect((await post(JSON.stringify(base), { [CSRF_HEADER]: "1", "content-type": type })).status, type).toBe(415);
    }
    expect((await post(JSON.stringify(base), { [CSRF_HEADER]: "1" })).status).toBe(415);
    expect((await post(base, { [CSRF_HEADER]: "1", "content-type": "Application/JSON; charset=utf-8" })).status).toBe(201);
  });
  it.each([
    ["invalid JSON", "{nope", 400, "body is not valid JSON"],
    ["a JSON array", "[1,2]", 400, "body must be a JSON object"],
    ["a JSON string", '"x"', 400, "body must be a JSON object"],
    ["a JSON number", "5", 400, "body must be a JSON object"],
    ["null", "null", 400, "body must be a JSON object"],
    ["an empty body", "", 400, "body is not valid JSON"],
  ])("rejects %s with %d and says why", async (_n, payload, status, message) => {
    const r = await post(payload);
    expect(r.status).toBe(status);
    expect((await body(r)).error).toBe(message);
  });
  it("rejects invalid fields with 400 and writes nothing", async () => {
    for (const bad of [{ ...base, mode: "deny" }, { ...base, name: "a b" }, { ...base, versions: [] }, { ...base, ecosystem: "gem" }]) {
      expect((await post(bad)).status).toBe(400);
    }
    expect(await audits()).toEqual([]);
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM overrides").first<{ n: number }>())?.n).toBe(0);
  });
  it("rejects an oversized body by its declared length, without reading any of it", async () => {
    const explodes = new ReadableStream<Uint8Array>({ pull() { throw new Error("the body must not be read"); } });
    const headers = { ...JSON_CSRF, "content-length": String(MAX_BODY_BYTES + 1) };
    const r = await call("/api/overrides", await user(), { method: "POST", headers, body: explodes, duplex: "half" } as RequestInit);
    expect(r.status).toBe(413);
    expect((await body(r)).error).toBe("request body too large");
  });
  it("rejects a body that declares a size under the limit but sends more", async () => {
    const big = new TextEncoder().encode(JSON.stringify({ ...base, note: "x".repeat(MAX_BODY_BYTES + 10) }));
    const r = await call("/api/overrides", await user(), { method: "POST", headers: { ...JSON_CSRF, "content-length": "50" }, body: chunked(big), duplex: "half" } as RequestInit);
    expect([400, 413]).toContain(r.status);
  });
  it("rejects an oversized body with no Content-Length, by the bytes actually received", async () => {
    const big = new TextEncoder().encode(JSON.stringify({ ...base, note: "x".repeat(MAX_BODY_BYTES + 10) }));
    const r = await call("/api/overrides", await user(), { method: "POST", headers: JSON_CSRF, body: chunked(big), duplex: "half" } as RequestInit);
    expect(r.status).toBe(413);
  });
  it("rejects a body that is not valid UTF-8, and says so", async () => {
    const r = await call("/api/overrides", await user(), { method: "POST", headers: JSON_CSRF, body: new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]) });
    expect(r.status).toBe(400);
    expect((await body(r)).error).toBe("body is not valid UTF-8");
  });
  it("answers a storage failure with a generic 500 and leaves D1 untouched", async () => {
    const broken = adminEnv({ PKG_INDEX: { put: async () => { throw new Error("KV down secret"); } } as unknown as KVNamespace });
    const r = await post(base, JSON_CSRF, undefined, broken);
    expect(r.status).toBe(500);
    expect(await r.text()).toBe('{"error":"internal error"}');
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM overrides").first<{ n: number }>())?.n).toBe(0);
  });
  it("answers 409 when the limit is reached", async () => {
    await env.DB.batch(Array.from({ length: 1000 }, (_, i) => env.DB.prepare("INSERT INTO overrides (ecosystem, package_name, mode, created_by, created_at) VALUES ('npm', ?, 'block', 'x', 'y')").bind(`p-${i}`)));
    expect((await post({ ...base, name: "one-more" })).status).toBe(409);
  });
});

/** A streamed body carries no Content-Length, so only the bytes received can bound it. */
function chunked(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({ start(c) { c.enqueue(bytes.slice(0, 5000)); c.enqueue(bytes.slice(5000)); c.close(); } });
}

describe("DELETE /api/overrides", () => {
  it("removes an override: 200 with what was removed, and an audit record", async () => {
    await post({ ...base, versions: ["1.0.0"] });
    const r = await del(base);
    expect(r.status).toBe(200);
    expect((await body(r)).removed).toMatchObject({ package_name: "left-pad", versions: ["1.0.0"] });
    expect(await env.PKG_INDEX.get("override:block:npm:left-pad")).toBeNull();
    expect((await audits()).map((a) => a.action)).toEqual(["override.add", "override.remove"]);
  });
  it("answers 404 for one that does not exist, and audits nothing", async () => {
    expect((await del(base)).status).toBe(404);
    expect(await audits()).toEqual([]);
  });
  it("needs authentication, the CSRF header and a JSON body", async () => {
    await post(base);
    expect((await del(base, JSON_CSRF, null)).status).toBe(401);
    expect((await del(base, { "content-type": "application/json" })).status).toBe(403);
    expect((await del(base, { [CSRF_HEADER]: "1", "content-type": "text/plain" })).status).toBe(415);
    expect(await env.PKG_INDEX.get("override:block:npm:left-pad")).not.toBeNull();
  });
  it("needs the mode, so removing an allow cannot remove a block by accident", async () => {
    await post({ ...base, mode: "block" });
    await post({ ...base, mode: "allow" });
    expect((await del({ ecosystem: "npm", name: "left-pad" })).status).toBe(400);
    await del({ ...base, mode: "allow" });
    expect(await env.PKG_INDEX.get("override:block:npm:left-pad")).not.toBeNull();
    expect(await env.PKG_INDEX.get("override:allow:npm:left-pad")).toBeNull();
  });
});

describe("methods", () => {
  it("allows only GET, POST and DELETE on /api/overrides", async () => {
    for (const method of ["PUT", "PATCH"]) expect((await call("/api/overrides", await user(), { method, headers: JSON_CSRF })).status, method).toBe(405);
    expect((await call("/api/overrides/other", await user(), { method: "POST", headers: JSON_CSRF })).status).toBe(405);
  });
});

describe("Chat notifications for override changes", () => {
  const withHook = () => adminEnv({ GCHAT_WEBHOOK: HOOK });

  it("announces an added block override, with who and what", async () => {
    const posted = chat();
    await post({ ...base, versions: ["1.3.0"], note: "malware in the wild" }, JSON_CSRF, undefined, withHook());
    expect(posted).toHaveLength(1);
    expect(posted[0]?.url).toBe(HOOK);
    expect(posted[0]?.text).toContain("*Block override added*");
    expect(posted[0]?.text).toContain("`left-pad` (npm)");
    expect(posted[0]?.text).toContain("`1.3.0`");
    expect(posted[0]?.text).toContain("`demo@example.com`");
    expect(posted[0]?.text).toContain("malware in the wild");
  });
  it("announces a removal", async () => {
    await post({ ...base, mode: "allow" });
    const posted = chat();
    await del({ ...base, mode: "allow" }, JSON_CSRF, undefined, withHook());
    expect(posted[0]?.text).toContain("*Allow override removed*");
  });
  it("says nothing, and does not fail, when no webhook is configured", async () => {
    const posted = chat();
    expect((await post(base)).status).toBe(201);
    expect(posted).toEqual([]);
  });
  it("still succeeds when Chat is down", async () => {
    chat(500);
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect((await post(base, JSON_CSRF, undefined, withHook())).status).toBe(201);
    expect(await env.PKG_INDEX.get("override:block:npm:left-pad")).not.toBeNull();
  });
  it("does not announce a rejected request", async () => {
    const posted = chat();
    await post({ ...base, mode: "nope" }, JSON_CSRF, undefined, withHook());
    await post(base, { "content-type": "application/json" }, undefined, withHook());
    expect(posted).toEqual([]);
  });
  it("cannot be made to post markup through the note", async () => {
    const posted = chat();
    await post({ ...base, note: "click <https://evil.example|here> *now*" }, JSON_CSRF, undefined, withHook());
    expect(posted[0]?.text).not.toContain("<https://evil");
    expect((posted[0]?.text.match(/<[^>]*>/g) ?? []).length).toBe(0);
  });
});

import { env } from "cloudflare:test";
import { handle, type Deps } from "../src/index.js";
import type { Env } from "../src/env.js";
import { resetStatusCache } from "../src/api/status.js";
import { AUD, NOW_MS, NOW_S, TEAM, fakeJwks, goodPayload, makeKey, reset, sign, type TestKey } from "./jwt-helpers.js";

export const FILES: Record<string, { type: string; body: string }> = {
  "/index.html": { type: "text/html; charset=utf-8", body: "<!doctype html><title>PkgGuard</title><div id=root></div>" },
  "/assets/app-abc123.js": { type: "text/javascript", body: "console.log(1)" },
  "/theme-init.js": { type: "text/javascript", body: "/* theme */" },
};
// Like the real binding, `/` is index.html.
FILES["/"] = FILES["/index.html"] as { type: string; body: string };

export const fakeAssets = {
  fetch: async (request: Request): Promise<Response> => {
    const file = FILES[new URL(request.url).pathname];
    return file ? new Response(request.method === "HEAD" ? null : file.body, { headers: { "content-type": file.type } }) : new Response("nope", { status: 404 });
  },
} as unknown as Fetcher;

export const adminEnv = (over: Partial<Env> = {}): Env => ({ ...env, ASSETS: fakeAssets, TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ...over });

let key: TestKey;
export async function setup(): Promise<void> {
  key ??= await makeKey("k1");
  reset();
  resetStatusCache();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM detections"),
    env.DB.prepare("DELETE FROM advisories"),
    env.DB.prepare("DELETE FROM sync_state"),
    env.DB.prepare("DELETE FROM refresh_runs"),
  ]);
  const list = await env.PKG_INDEX.list();
  await Promise.all(list.keys.map((k) => env.PKG_INDEX.delete(k.name)));
}

export const user = async (aud: string = AUD, email = "demo@example.com"): Promise<string> =>
  sign(key, { payload: goodPayload({ aud: [aud], email }) });
export const serviceToken = async (aud: string = AUD, clientId = "tok123.access"): Promise<string> =>
  sign(key, { payload: goodPayload({ aud: [aud], email: undefined, common_name: clientId }) });

export const deps = (): Deps => ({ now: () => new Date(NOW_MS), fetchJwks: fakeJwks(key).fetch });

export async function call(path: string, token: string | null, init: RequestInit = {}, e: Env = adminEnv()): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token !== null) headers.set("cf-access-jwt-assertion", token);
  return handle(new Request(`https://pkgguard.example.com${path}`, { ...init, headers }), e, deps());
}

export const iso = (offsetSeconds = 0): string => new Date((NOW_S + offsetSeconds) * 1000).toISOString();

export async function addDetection(row: Partial<Record<string, string | null>> & { ts?: string }): Promise<void> {
  const r = { ts: iso(-60), ecosystem: "npm", package_name: "left-pad", version: "1.0.0", purl: null, verdict: "allowed", reason: null, osv_ids: null, user_email: "demo@example.com", src_ip: "203.0.113.9", source: "index", ...row };
  await env.DB.prepare(
    "INSERT INTO detections (ts, ecosystem, package_name, version, purl, verdict, reason, osv_ids, user_email, src_ip, source) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
  )
    .bind(r.ts, r.ecosystem, r.package_name, r.version, r.purl, r.verdict, r.reason, r.osv_ids, r.user_email, r.src_ip, r.source)
    .run();
}

export async function addAdvisory(a: { ecosystem: string; id: string; name: string; kind: "malware" | "vulnerability"; severity?: string | null; summary?: string; withdrawn?: number }): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO advisories (ecosystem, osv_id, package_name, namespace, kind, severity, summary, ranges_json, withdrawn, modified) VALUES (?,?,?,?,?,?,?,?,?,?)",
  )
    .bind(a.ecosystem, a.id, a.name, null, a.kind, a.severity ?? null, a.summary ?? `summary of ${a.id}`, '{"r":[],"v":[]}', a.withdrawn ?? 0, iso())
    .run();
}

export const putKv = (key: string, value: unknown): Promise<void> => env.PKG_INDEX.put(key, JSON.stringify(value));

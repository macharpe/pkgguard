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

export const workflowCalls: Array<{ id: string; params: unknown }> = [];
export const failNextWorkflowCreate = { value: false };
/** Records start requests instead of running anything. */
export const fakeRefresh = {
  create: async (options: { id: string; params: unknown }) => {
    if (failNextWorkflowCreate.value) {
      failNextWorkflowCreate.value = false;
      throw new Error("workflow service unavailable");
    }
    workflowCalls.push(options);
    return { id: options.id };
  },
} as unknown as Workflow;

export const adminEnv = (over: Partial<Env> = {}): Env => ({ ...env, ASSETS: fakeAssets, REFRESH: fakeRefresh, TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ...over });

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
    env.DB.prepare("DELETE FROM refresh_items"),
    env.DB.prepare("DELETE FROM audit_log"),
  ]);
  workflowCalls.length = 0;
  failNextWorkflowCreate.value = false;
  const list = await env.PKG_INDEX.list();
  await Promise.all(list.keys.map((k) => env.PKG_INDEX.delete(k.name)));
}

export const user = async (aud: string = AUD, email = "demo@example.com"): Promise<string> =>
  sign(key, { payload: goodPayload({ aud: [aud], email }) });
export const serviceToken = async (aud: string = AUD, clientId = "tok123.access"): Promise<string> =>
  sign(key, { payload: goodPayload({ aud: [aud], email: undefined, common_name: clientId }) });

export const background: Promise<unknown>[] = [];
export const deps = (): Deps => ({ now: () => new Date(NOW_MS), fetchJwks: fakeJwks(key).fetch, waitUntil: (work) => void background.push(work) });
/** Waits for background work such as Chat notifications, so a test can assert on it. */
export const flushBackground = async (): Promise<void> => {
  await Promise.allSettled(background.splice(0));
};

export async function call(path: string, token: string | null, init: RequestInit = {}, e: Env = adminEnv()): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token !== null) headers.set("cf-access-jwt-assertion", token);
  const response = await handle(new Request(`https://pkgguard.example.com${path}`, { ...init, headers }), e, deps());
  await flushBackground();
  return response;
}

export const iso = (offsetSeconds = 0): string => new Date((NOW_S + offsetSeconds) * 1000).toISOString();

export async function addDetection(row: Partial<Record<string, string | null>> & { ts?: string }): Promise<void> {
  const r = { ts: iso(-60), ecosystem: "npm", package_name: "left-pad", version: "1.0.0", purl: null, verdict: "allowed", reason: null, osv_ids: null, user_email: "demo@example.com", src_ip: "203.0.113.9", source: "index", reference: null, ...row };
  await env.DB.prepare(
    "INSERT INTO detections (ts, ecosystem, package_name, version, purl, verdict, reason, osv_ids, user_email, src_ip, source, reference) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
  )
    .bind(r.ts, r.ecosystem, r.package_name, r.version, r.purl, r.verdict, r.reason, r.osv_ids, r.user_email, r.src_ip, r.source, r.reference)
    .run();
}

export async function addAdvisory(a: { ecosystem: string; id: string; name: string; kind: "malware" | "vulnerability"; severity?: string | null; cvss?: unknown; summary?: string; withdrawn?: number }): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO advisories (ecosystem, osv_id, package_name, namespace, kind, severity, summary, ranges_json, withdrawn, modified, cvss_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
  )
    .bind(a.ecosystem, a.id, a.name, null, a.kind, a.severity ?? null, a.summary ?? `summary of ${a.id}`, '{"r":[],"v":[]}', a.withdrawn ?? 0, iso(), a.cvss === undefined ? null : JSON.stringify(a.cvss))
    .run();
}

export const putKv = (key: string, value: unknown): Promise<void> => env.PKG_INDEX.put(key, JSON.stringify(value));

import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import type { GatewayMiddlewareContext } from "@cloudflare/zt-types";
import { buildKvEntry, distill, kvKey, type OsvRecord } from "@pkgguard/core";
import { vi } from "vitest";
import { GatewayMiddleware } from "../src/index.js";
import type { Env } from "../src/env.js";

export const NPM = "https://registry.npmjs.org";
export const PYPI = "https://files.pythonhosted.org/packages/ab/cd/ef0123";

export const tarball = (name: string, version: string): string => `${NPM}/${name}/-/${name}-${version}.tgz`;

export interface Detection {
  ecosystem: string;
  package_name: string;
  version: string;
  purl: string;
  verdict: string;
  reason: string | null;
  osv_ids: string | null;
  user_email: string | null;
  src_ip: string | null;
  source: string;
  reference: string | null;
}

export interface RunOptions {
  env?: Partial<Env>;
  identity?: () => Promise<{ email?: string } | null>;
  headers?: Record<string, string>;
}

export function gatewayContext(identity?: RunOptions["identity"]): GatewayMiddlewareContext {
  return {
    srcIp: "203.0.113.9",
    srcPort: 5555,
    networkProtocol: "tcp",
    host: "registry.npmjs.org",
    uri: "/",
    accountId: "acct",
    policyId: "policy",
    identity: identity ?? (async () => ({ email: "dev@example.com" })),
    devicePosture: async () => ({}) as never,
  };
}

export async function run(url: string, options: RunOptions = {}) {
  const ctx = createExecutionContext();
  const middleware = new GatewayMiddleware(ctx, { ...env, ...options.env } as Env);
  const upstream = new Response("upstream-bytes", { status: 200 });
  const next = vi.fn(async (_request: Request) => upstream);
  const response = await middleware.handle(new Request(url, { headers: options.headers ?? {} }), gatewayContext(options.identity), next);
  await waitOnExecutionContext(ctx);
  return { response, next, upstream };
}

export async function detections(): Promise<Detection[]> {
  const { results } = await env.DB.prepare(
    "SELECT ecosystem, package_name, version, purl, verdict, reason, osv_ids, user_email, src_ip, source, reference FROM detections ORDER BY id",
  ).all<Detection>();
  return results;
}

export async function reset(): Promise<void> {
  await env.DB.exec("DELETE FROM detections");
  const { keys } = await env.PKG_INDEX.list();
  await Promise.all(keys.map((k) => env.PKG_INDEX.delete(k.name)));
}

/** Seeds the index exactly the way the bootstrap would: distill, then buildKvEntry. */
export async function seed(record: OsvRecord, ecosystem: "npm" | "pypi", name: string): Promise<void> {
  const rows = distill(record).filter((r) => r.ecosystem === ecosystem && r.packageName === name);
  const entry = buildKvEntry(rows, "2026-11-06T00:00:00Z");
  const key = kvKey(ecosystem, name);
  if (!entry || !key) throw new Error(`cannot seed ${name}`);
  await env.PKG_INDEX.put(key, JSON.stringify(entry));
}

export const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

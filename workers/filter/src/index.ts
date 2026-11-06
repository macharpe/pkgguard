import { WorkerEntrypoint } from "cloudflare:workers";
import type { GatewayMiddlewareContext, GatewayMiddlewareNext } from "@cloudflare/zt-types";
import { parsePackageUrl, type ParsedPackage } from "@pkgguard/core";
import { decide, type Decision, type DecideDeps } from "./decide.js";
import { recordDetection } from "./detections.js";
import { readSettings, type Env } from "./env.js";
import { blockPage } from "./page.js";

const IDENTITY_TIMEOUT_MS = 250;

const lookupFailed: Decision = { block: false, verdict: "error", reason: "lookup-error", osvIds: [], source: "index" };

async function identityEmail(context: GatewayMiddlewareContext): Promise<string | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const identity = await Promise.race([
      context.identity(),
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), IDENTITY_TIMEOUT_MS);
      }),
    ]);
    return identity?.email ?? null;
  } catch {
    return null;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Gateway invokes this class by name over Workers RPC; renaming it silently disables enforcement.
 * Gateway fails closed on a Worker error, so every path here fails open.
 */
export class GatewayMiddleware extends WorkerEntrypoint<Env> {
  async handle(request: Request, context: GatewayMiddlewareContext, next: GatewayMiddlewareNext): Promise<Response> {
    let pkg: ParsedPackage | null = null;
    try {
      pkg = parsePackageUrl(request.url);
    } catch {
      pkg = null;
    }
    if (pkg === null) return next(request);

    const settings = readSettings(this.env);
    const deps: DecideDeps = {
      kv: this.env.PKG_INDEX,
      fetch: (input, init) => fetch(input, init),
      osvTimeoutMs: settings.osvTimeoutMs,
      now: () => new Date().toISOString(),
    };

    // Identity is resolved now because the context's RPC stubs are not guaranteed to outlive this call.
    const [decision, email] = await Promise.all([
      decide(pkg, deps).catch((err: unknown): Decision => {
        console.error(JSON.stringify({ msg: "decision failed, failing open", error: String(err) }));
        return lookupFailed;
      }),
      identityEmail(context),
    ]);

    const blocking = decision.block && settings.enforce;
    // Observe-only: what would have been blocked is recorded as flagged, so "blocked" always means blocked.
    const verdict = decision.block && !settings.enforce ? "flagged" : decision.verdict;

    const now = deps.now();
    const pending: Promise<unknown>[] = [
      recordDetection(this.env.DB, pkg, decision, verdict, { email, srcIp: context.srcIp ?? null }, now),
    ];
    if (decision.cache) {
      pending.push(
        this.env.PKG_INDEX.put(decision.cache.key, JSON.stringify(decision.cache.value), {
          expirationTtl: settings.cacheTtlSeconds,
        }),
      );
    }
    for (const work of pending) {
      this.ctx.waitUntil(
        work.catch((err: unknown) => console.error(JSON.stringify({ msg: "background write failed", error: String(err) }))),
      );
    }

    return blocking ? blockPage(pkg, decision) : next(request);
  }
}

export default {
  fetch(): Response {
    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

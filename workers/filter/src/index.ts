import { WorkerEntrypoint } from "cloudflare:workers";
import type { GatewayMiddlewareContext, GatewayMiddlewareNext } from "@cloudflare/zt-types";
import { newReference, parsePackageCandidates, type ParsedPackage } from "@pkgguard/core";
import { decide, fullName, mostSevere, type Decision, type DecideDeps } from "./decide.js";
import { maybeAlertMalware } from "./alert.js";
import { recordDetection } from "./detections.js";
import { enforces, readSettings, type Env } from "./env.js";
import { blockResponse } from "./page.js";

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
 * What can be said about a request this Worker did not recognise without recording anything about the package:
 * the host (a registry, not a person), the kind of file and how deep the path is. The kind comes from a fixed list,
 * never from the file name, because a name or version that happens to look like an extension would leak. The query
 * string, where a token could ride, is never read.
 */
const FILE_KINDS = /\.(tar\.gz|tar\.bz2|tar\.xz|tgz|tar|zip|whl|egg|gem|crate|nupkg|jar|json|xml|html|asc|metadata)$/i;

function describeUnparsed(rawUrl: string): { host: string | null; extension: string; depth: number } {
  try {
    const url = new URL(rawUrl);
    const segments = url.pathname.split("/");
    const extension = FILE_KINDS.exec(segments.at(-1) ?? "")?.[0].toLowerCase() ?? "";
    return { host: url.hostname, extension, depth: segments.length - 1 };
  } catch {
    return { host: null, extension: "", depth: 0 };
  }
}

/**
 * Gateway invokes this class by name over Workers RPC; renaming it silently disables enforcement.
 * Gateway fails closed on a Worker error, so every path here fails open.
 */
export class GatewayMiddleware extends WorkerEntrypoint<Env> {
  async handle(request: Request, context: GatewayMiddlewareContext, next: GatewayMiddlewareNext): Promise<Response> {
    let candidates: ParsedPackage[];
    try {
      candidates = parsePackageCandidates(request.url);
    } catch {
      candidates = [];
    }
    if (candidates.length === 0) {
      // The Forward rule only sends traffic Gateway classified as a package download, so a request we cannot read means
      // Gateway's classifier and our parsers disagree. That is the only signal of it: nothing else records the request.
      console.warn(JSON.stringify({ msg: "forwarded request is not a package download this Worker recognises", ...describeUnparsed(request.url) }));
      return next(request);
    }

    const settings = readSettings(this.env);
    const deps: DecideDeps = {
      kv: this.env.PKG_INDEX,
      fetch: (input, init) => fetch(input, init),
      osvTimeoutMs: settings.osvTimeoutMs,
      now: () => new Date().toISOString(),
    };

    // Identity is resolved now because the context's RPC stubs are not guaranteed to outlive this call.
    const [decided, email] = await Promise.all([
      Promise.all(
        candidates.map(async (candidate) => ({
          pkg: candidate,
          decision: await decide(candidate, deps).catch((err: unknown): Decision => {
            console.error(JSON.stringify({ msg: "decision failed, failing open", error: String(err) }));
            return lookupFailed;
          }),
        })),
      ),
      identityEmail(context),
    ]);
    // Most downloads have one reading. When a file name has several, the most severe verdict decides.
    const { pkg, decision } = mostSevere(decided as [(typeof decided)[number], ...typeof decided]);

    const blocking = decision.block && enforces(settings, pkg.ecosystem);
    // Observe-only (everywhere, or for this ecosystem): what would have been blocked is recorded as flagged, so "blocked" always means blocked.
    const verdict = decision.block && !blocking ? "flagged" : decision.verdict;

    const now = deps.now();
    // One code ties the page the developer sees, the Chat alert and the detection row together.
    const reference = decision.block ? newReference((bytes) => (crypto.getRandomValues(bytes), bytes)) : null;
    const pending: Promise<unknown>[] = [
      recordDetection(this.env.DB, pkg, decision, verdict, { email, srcIp: context.srcIp ?? null }, now, reference),
    ];
    for (const { decision: reading } of decided) {
      if (!reading.cache) continue;
      pending.push(
        this.env.PKG_INDEX.put(reading.cache.key, JSON.stringify(reading.cache.value), {
          expirationTtl: settings.cacheTtlSeconds,
        }),
      );
    }
    if (decision.block) {
      pending.push(
        maybeAlertMalware(
          { kv: this.env.PKG_INDEX, fetch: deps.fetch, webhook: this.env.GCHAT_WEBHOOK },
          {
            ecosystem: pkg.ecosystem,
            name: fullName(pkg),
            version: pkg.version,
            user: email,
            blocked: blocking,
            reason: decision.reason === "override" ? "override" : "osv-malware",
            osvIds: decision.osvIds,
            reference,
          },
        ),
      );
    }
    for (const work of pending) {
      this.ctx.waitUntil(
        work.catch((err: unknown) => console.error(JSON.stringify({ msg: "background write failed", error: String(err) }))),
      );
    }

    return blocking ? blockResponse(request, pkg, decision, reference, this.env.SUPPORT_CONTACT) : next(request);
  }
}

export default {
  fetch(): Response {
    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

import { AccessError, readAssertion, verifyAccessJwt, type Actor } from "./access-jwt.js";
import { advisories } from "./api/advisories.js";
import { overridesAdd, overridesList, overridesRemove } from "./api/overrides.js";
import { detections } from "./api/detections.js";
import { refreshHistory, refreshStatus, startRefresh } from "./api/refresh.js";
import { status } from "./api/status.js";
import { whoami } from "./api/whoami.js";
import type { Env } from "./env.js";
import { HttpError, errorResponse, json } from "./http.js";
import { launchRefresh } from "./refresh/launch.js";
import type { RunKind } from "./refresh/runs.js";

export { RefreshWorkflow } from "./refresh/workflow.js";

/** No inline script is allowed: the theme bootstrap is an external file. Kumo/Base UI set inline styles, hence style-src. */
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
  "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export interface Deps {
  now: () => Date;
  /** Runs background work after the response, such as a Chat notification. */
  waitUntil: (work: Promise<unknown>) => void;
  fetchJwks?: (url: string) => Promise<Response>;
}

const isApiPath = (pathname: string): boolean => pathname === "/api" || pathname.startsWith("/api/");

/**
 * Dashboard and API share one Access application, so one cookie and one audience. A service token may only
 * call the API: Access cannot scope it by path inside one application, so it is refused here.
 */
export async function authenticate(request: Request, env: Env, deps: Deps): Promise<Actor> {
  const token = readAssertion(request);
  if (token === null) throw new HttpError(401, "missing Access assertion");
  let actor: Actor;
  try {
    actor = await verifyAccessJwt(token, { teamDomain: env.TEAM_DOMAIN }, env.ACCESS_AUD, deps.fetchJwks, deps.now().getTime());
  } catch (err) {
    if (err instanceof AccessError) throw new HttpError(403, "invalid Access assertion");
    throw err;
  }
  if (actor.kind === "service-token" && !isApiPath(new URL(request.url).pathname)) {
    throw new HttpError(403, "service tokens may only call the API");
  }
  return actor;
}

/**
 * The Access cookie is sent on cross-site requests, so a page on another origin could otherwise POST here as the user.
 * A custom header cannot be sent cross-origin without a CORS preflight, and this Worker never approves one.
 */
export const CSRF_HEADER = "x-pkgguard-csrf";
function requireCsrfHeader(request: Request): void {
  if (request.headers.get(CSRF_HEADER) !== "1") throw new HttpError(403, "missing CSRF header");
}

export async function route(request: Request, env: Env, deps: Deps): Promise<Response> {
  const url = new URL(request.url);
  const actor = await authenticate(request, env, deps);

  if (request.method === "POST" && url.pathname === "/api/refresh") {
    requireCsrfHeader(request);
    return startRefresh(env, actor, deps.now());
  }
  // Only GET and POST: the zone's managed WAF blocks every other method ("Anomaly:Method - Not GET or POST"),
  // so removal is a POST to its own path rather than a DELETE.
  if (request.method === "POST" && (url.pathname === "/api/overrides" || url.pathname === "/api/overrides/remove")) {
    requireCsrfHeader(request);
    const context = { env, actor, now: deps.now(), waitUntil: deps.waitUntil };
    return url.pathname === "/api/overrides" ? overridesAdd(request, context) : overridesRemove(request, context);
  }
  if (request.method !== "GET" && request.method !== "HEAD") throw new HttpError(405, "method not allowed");

  switch (url.pathname) {
    case "/api/whoami":
      return whoami(actor);
    case "/api/status":
      return status(env, deps.now());
    case "/api/detections":
      return detections(env, url);
    case "/api/advisories":
      return advisories(env, url);
    case "/api/overrides":
      return overridesList(env);
    case "/api/refresh/history":
      return refreshHistory(env, url);
    default:
      if (url.pathname.startsWith("/api/refresh/")) return refreshStatus(env, url.pathname.slice("/api/refresh/".length), deps.now());
      if (isApiPath(url.pathname)) throw new HttpError(404, "not found");
      return serveAsset(request, env);
  }
}

/** The dashboard is a static build. It is only reachable here, so every asset is behind the JWT check above. */
async function serveAsset(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  // Asked for exactly as the browser did, so the Assets binding applies its own HTML handling (index.html at /, no redirects).
  const path = url.pathname;
  const upstream = await env.ASSETS.fetch(new Request(new URL(path, url), { method: request.method }));
  if (upstream.status !== 200) throw new HttpError(404, "not found");

  const response = new Response(upstream.body, upstream);
  const hashed = path.startsWith("/assets/");
  response.headers.set("cache-control", hashed ? "private, max-age=31536000, immutable" : "no-store");
  response.headers.set("x-content-type-options", "nosniff");
  response.headers.set("referrer-policy", "no-referrer");
  response.headers.set("x-frame-options", "DENY");
  // Decided by what is served, not by the URL: the page itself is requested as "/".
  if (response.headers.get("content-type")?.startsWith("text/html")) response.headers.set("content-security-policy", CSP);
  return response;
}

/** Maps every failure to a JSON response. Only HttpError messages are shown to the caller. */
export async function handle(request: Request, env: Env, deps: Deps): Promise<Response> {
  try {
    return await route(request, env, deps);
  } catch (err) {
    if (err instanceof HttpError) return errorResponse(err.status, err.message);
    console.error("unhandled", err instanceof Error ? err.message : String(err));
    return json({ error: "internal error" }, 500);
  }
}

const CRON_KINDS: Record<string, RunKind> = { "0 3 1 * *": "monthly", "0 4 * * *": "daily" };

/** Runs the same idempotent delta as a manual refresh. Skips quietly if one is already running. */
export async function runScheduled(controller: Pick<ScheduledController, "cron" | "scheduledTime">, env: Env): Promise<void> {
  const kind = CRON_KINDS[controller.cron];
  if (kind === undefined) {
    console.error("unknown cron schedule", controller.cron);
    return;
  }
  const result = await launchRefresh(env, { kind, trigger: "cron" }, new Date(controller.scheduledTime));
  if (!result.started) console.log("refresh skipped: one is already running", result.activeId);
}

export default {
  fetch: (request: Request, env: Env, ctx: ExecutionContext): Promise<Response> =>
    handle(request, env, { now: () => new Date(), waitUntil: (work) => ctx.waitUntil(work) }),
  scheduled: (controller: ScheduledController, env: Env, ctx: ExecutionContext): void => {
    ctx.waitUntil(runScheduled(controller, env));
  },
} satisfies ExportedHandler<Env>;

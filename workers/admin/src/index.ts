import { AccessError, readAssertion, verifyAccessJwt, type Actor } from "./access-jwt.js";
import { advisories } from "./api/advisories.js";
import { detections } from "./api/detections.js";
import { status } from "./api/status.js";
import { whoami } from "./api/whoami.js";
import type { Env } from "./env.js";
import { HttpError, errorResponse, json } from "./http.js";

/** No inline script is allowed: the theme bootstrap is an external file. Kumo/Base UI set inline styles, hence style-src. */
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; " +
  "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export interface Deps {
  now: () => Date;
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

export async function route(request: Request, env: Env, deps: Deps): Promise<Response> {
  const url = new URL(request.url);
  const actor = await authenticate(request, env, deps);

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
    default:
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

export default {
  fetch: (request: Request, env: Env): Promise<Response> => handle(request, env, { now: () => new Date() }),
} satisfies ExportedHandler<Env>;

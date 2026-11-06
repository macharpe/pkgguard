import { AccessError, readAssertion, verifyAccessJwt, type Actor } from "./access-jwt.js";
import { advisories } from "./api/advisories.js";
import { detections } from "./api/detections.js";
import { status } from "./api/status.js";
import { whoami } from "./api/whoami.js";
import type { Env } from "./env.js";
import { HttpError, errorResponse, json } from "./http.js";

const PLACEHOLDER_PAGE = `<!doctype html><meta charset="utf-8"><title>PkgGuard</title><h1>PkgGuard admin</h1><p>The dashboard is not built yet.</p>`;

export interface Deps {
  now: () => Date;
  fetchJwks?: (url: string) => Promise<Response>;
}

/** The `/api/*` path is a separate Access application with its own audience, so each path only accepts its own token. */
export const audienceFor = (pathname: string, env: Env): string =>
  pathname === "/api" || pathname.startsWith("/api/") ? env.ACCESS_AUD_API : env.ACCESS_AUD_UI;

export async function authenticate(request: Request, env: Env, deps: Deps): Promise<Actor> {
  const token = readAssertion(request);
  if (token === null) throw new HttpError(401, "missing Access assertion");
  const audience = audienceFor(new URL(request.url).pathname, env);
  try {
    return await verifyAccessJwt(token, { teamDomain: env.TEAM_DOMAIN }, audience, deps.fetchJwks, deps.now().getTime());
  } catch (err) {
    if (err instanceof AccessError) throw new HttpError(403, "invalid Access assertion");
    throw err;
  }
}

export async function route(request: Request, env: Env, deps: Deps): Promise<Response> {
  const url = new URL(request.url);
  const actor = await authenticate(request, env, deps);

  if (request.method !== "GET" && request.method !== "HEAD") throw new HttpError(405, "method not allowed");

  switch (url.pathname) {
    case "/":
      return new Response(PLACEHOLDER_PAGE, {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
      });
    case "/api/whoami":
      return whoami(actor);
    case "/api/status":
      return status(env, deps.now());
    case "/api/detections":
      return detections(env, url);
    case "/api/advisories":
      return advisories(env, url);
    default:
      throw new HttpError(404, "not found");
  }
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

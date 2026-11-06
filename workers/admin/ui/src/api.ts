import type {
  AddOverrideRequest,
  AddOverrideResponse,
  AdvisoriesResponse,
  DetectionsResponse,
  OverridesResponse,
  RefreshHistoryResponse,
  RefreshRunInfo,
  RemoveOverrideRequest,
  RemoveOverrideResponse,
  StartRefreshResponse,
  StatusResponse,
  WhoamiResponse,
} from "../../src/api-types.js";

/** Sent on every write. A browser cannot add it to a cross-origin request without a preflight the server never approves. */
export const CSRF_HEADER = "x-pkgguard-csrf";

/**
 * `session`: the Access session ended. Access answers an expired API call with a redirect to its login page,
 * which with `redirect: "manual"` surfaces as an opaque redirect, or as a 401/403.
 */
export class ApiError extends Error {
  constructor(
    readonly kind: "session" | "http" | "network",
    message: string,
    readonly status?: number,
    /** The parsed JSON error body, when there was one: a 409 carries the id of the run already in progress. */
    readonly body?: Record<string, unknown>,
  ) {
    super(message);
  }
}

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

type Method = "GET" | "POST";

async function request<T>(
  method: Method,
  path: string,
  params: Record<string, string | undefined>,
  signal: AbortSignal | undefined,
  fetchFn: FetchFn,
  json?: unknown,
): Promise<T> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== "") query.set(key, value);
  const url = query.size > 0 ? `${path}?${query}` : path;
  const headers: Record<string, string> = {
    accept: "application/json",
    ...(method === "POST" ? { [CSRF_HEADER]: "1" } : {}),
    ...(json !== undefined ? { "content-type": "application/json" } : {}),
  };

  let response: Response;
  try {
    response = await fetchFn(url, {
      method,
      headers,
      redirect: "manual",
      credentials: "same-origin",
      ...(json !== undefined ? { body: JSON.stringify(json) } : {}),
      ...(signal ? { signal } : {}),
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("network", "Could not reach the server");
  }
  if (response.type === "opaqueredirect" || response.status === 401) throw new ApiError("session", "Your session has ended", response.status);
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    let body: Record<string, unknown> | undefined;
    try {
      const parsed = (await response.json()) as unknown;
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
      if (typeof body?.["error"] === "string") message = body["error"];
    } catch {
      /* keep the generic message */
    }
    // A 403 from the server is an expired or invalid Access assertion, except on a write, where it can be the CSRF guard.
    if (response.status === 403 && method === "GET") throw new ApiError("session", "Your session has ended", 403, body);
    throw new ApiError("http", message, response.status, body);
  }
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError("http", "The server sent an unreadable response", response.status);
  }
}

export const getJson = <T>(path: string, params: Record<string, string | undefined> = {}, signal?: AbortSignal, fetchFn: FetchFn = (i, n) => fetch(i, n)): Promise<T> =>
  request<T>("GET", path, params, signal, fetchFn);

export const postJson = <T>(path: string, signal?: AbortSignal, fetchFn: FetchFn = (i, n) => fetch(i, n), json?: unknown): Promise<T> =>
  request<T>("POST", path, {}, signal, fetchFn, json);

export const api = {
  status: (signal?: AbortSignal) => getJson<StatusResponse>("/api/status", {}, signal),
  whoami: (signal?: AbortSignal) => getJson<WhoamiResponse>("/api/whoami", {}, signal),
  detections: (params: { verdict?: string; ecosystem?: string; reference?: string; before?: string }, signal?: AbortSignal) =>
    getJson<DetectionsResponse>("/api/detections", { limit: "25", ...params }, signal),
  advisories: (params: { q: string; version?: string; ecosystem?: string }, signal?: AbortSignal) =>
    getJson<AdvisoriesResponse>("/api/advisories", params, signal),
  startRefresh: (signal?: AbortSignal) => postJson<StartRefreshResponse>("/api/refresh", signal),
  refreshRun: (id: string, signal?: AbortSignal) => getJson<RefreshRunInfo>(`/api/refresh/${encodeURIComponent(id)}`, {}, signal),
  overrides: (signal?: AbortSignal) => getJson<OverridesResponse>("/api/overrides", {}, signal),
  addOverride: (body: AddOverrideRequest) => postJson<AddOverrideResponse>("/api/overrides", undefined, undefined, body),
  removeOverride: (body: RemoveOverrideRequest) => postJson<RemoveOverrideResponse>("/api/overrides/remove", undefined, undefined, body),
  refreshHistory: (signal?: AbortSignal) => getJson<RefreshHistoryResponse>("/api/refresh/history", { limit: "5" }, signal),
};

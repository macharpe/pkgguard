import type { AdvisoriesResponse, DetectionsResponse, StatusResponse, WhoamiResponse } from "../../src/api-types.js";

/**
 * `session`: the Access session ended. Access answers an expired API call with a redirect to its login page,
 * which with `redirect: "manual"` surfaces as an opaque redirect, or as a 401/403.
 */
export class ApiError extends Error {
  constructor(
    readonly kind: "session" | "http" | "network",
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export async function getJson<T>(path: string, params: Record<string, string | undefined> = {}, signal?: AbortSignal, fetchFn: FetchFn = (i, n) => fetch(i, n)): Promise<T> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== "") query.set(key, value);
  const url = query.size > 0 ? `${path}?${query}` : path;

  let response: Response;
  try {
    response = await fetchFn(url, { headers: { accept: "application/json" }, redirect: "manual", credentials: "same-origin", ...(signal ? { signal } : {}) });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") throw err;
    throw new ApiError("network", "Could not reach the server");
  }
  if (response.type === "opaqueredirect" || response.status === 401 || response.status === 403) {
    throw new ApiError("session", "Your session has ended", response.status);
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { error?: unknown };
      if (typeof body.error === "string") message = body.error;
    } catch {
      /* keep the generic message */
    }
    throw new ApiError("http", message, response.status);
  }
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError("http", "The server sent an unreadable response", response.status);
  }
}

export const api = {
  status: (signal?: AbortSignal) => getJson<StatusResponse>("/api/status", {}, signal),
  whoami: (signal?: AbortSignal) => getJson<WhoamiResponse>("/api/whoami", {}, signal),
  detections: (params: { verdict?: string; ecosystem?: string; before?: string }, signal?: AbortSignal) =>
    getJson<DetectionsResponse>("/api/detections", { limit: "25", ...params }, signal),
  advisories: (params: { q: string; version?: string; ecosystem?: string }, signal?: AbortSignal) =>
    getJson<AdvisoriesResponse>("/api/advisories", params, signal),
};

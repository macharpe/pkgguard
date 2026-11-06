export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const SECURITY_HEADERS = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
} as const;

export const json = (data: unknown, status = 200): Response => Response.json(data, { status, headers: SECURITY_HEADERS });

export const errorResponse = (status: number, message: string): Response => json({ error: message }, status);

export function intParam(url: URL, name: string, fallback: number, max: number): number {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === "") return fallback;
  if (!/^\d+$/.test(raw)) throw new HttpError(400, `${name} must be a non-negative integer`);
  const n = Number.parseInt(raw, 10);
  if (n < 1 || n > max) throw new HttpError(400, `${name} must be between 1 and ${max}`);
  return n;
}

export function enumParam<T extends string>(url: URL, name: string, allowed: readonly T[]): T | null {
  const raw = url.searchParams.get(name);
  if (raw === null || raw === "") return null;
  if (!(allowed as readonly string[]).includes(raw)) throw new HttpError(400, `${name} must be one of ${allowed.join(", ")}`);
  return raw as T;
}

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

export const MAX_BODY_BYTES = 8 * 1024;

/**
 * Reads a small JSON object body. The size is enforced on the bytes actually received, not only on Content-Length,
 * which a client can omit or understate.
 */
export async function readJsonBody(request: Request, maxBytes = MAX_BODY_BYTES): Promise<Record<string, unknown>> {
  if (!(request.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "send the body as application/json");
  }
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) throw new HttpError(413, "request body too large");

  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new HttpError(413, "request body too large");
      }
      chunks.push(value);
    }
  }
  let text: string;
  try {
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new HttpError(400, "body is not valid UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, "body is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new HttpError(400, "body must be a JSON object");
  return parsed as Record<string, unknown>;
}

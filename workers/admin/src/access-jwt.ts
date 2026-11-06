/**
 * Verifies the Cf-Access-Jwt-Assertion header. Access already gates the hostname; this is the second
 * lock, so a request that reaches the Worker by any other path is never trusted.
 */

export interface AccessConfig {
  /** `<team>.cloudflareaccess.com` */
  teamDomain: string;
}

export type Actor = { kind: "user"; email: string } | { kind: "service-token"; clientId: string };

export class AccessError extends Error {}

export type FetchLike = (url: string) => Promise<Response>;

interface Jwk {
  kid: string;
  kty: string;
  n: string;
  e: string;
  alg?: string;
}

const CLOCK_SKEW_SECONDS = 30;
const JWKS_TTL_MS = 10 * 60_000;
/** An unknown `kid` triggers one refetch, but never more often than this, so junk tokens cannot hammer Access. */
const REFETCH_COOLDOWN_MS = 30_000;

interface Cache {
  keys: Map<string, CryptoKey>;
  fetchedAt: number;
}
const caches = new Map<string, Cache>();

/** Test hook: forget cached keys. */
export function resetJwksCache(): void {
  caches.clear();
}

function b64urlToBytes(input: string): Uint8Array {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const bin = atob(input.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function decodeJson(part: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(b64urlToBytes(part)));
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch {
    throw new AccessError("malformed token");
  }
}

async function loadKeys(teamDomain: string, fetchFn: FetchLike, now: number): Promise<Cache> {
  let response: Response;
  try {
    response = await fetchFn(`https://${teamDomain}/cdn-cgi/access/certs`);
  } catch {
    throw new AccessError("could not fetch the Access signing keys");
  }
  if (!response.ok) throw new AccessError(`Access signing keys returned HTTP ${response.status}`);
  let body: { keys?: unknown };
  try {
    body = (await response.json()) as { keys?: unknown };
  } catch {
    throw new AccessError("Access signing keys were not JSON");
  }
  if (!Array.isArray(body.keys)) throw new AccessError("Access signing keys had no key set");
  const keys = new Map<string, CryptoKey>();
  for (const raw of body.keys as Jwk[]) {
    if (raw?.kty !== "RSA" || typeof raw.kid !== "string") continue;
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: raw.n, e: raw.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    keys.set(raw.kid, key);
  }
  if (keys.size === 0) throw new AccessError("Access signing keys held no usable RSA key");
  const cache = { keys, fetchedAt: now };
  caches.set(teamDomain, cache);
  return cache;
}

async function keyFor(kid: string, teamDomain: string, fetchFn: FetchLike, now: number): Promise<CryptoKey> {
  let cache = caches.get(teamDomain);
  if (!cache || now - cache.fetchedAt > JWKS_TTL_MS) cache = await loadKeys(teamDomain, fetchFn, now);
  let key = cache.keys.get(kid);
  if (!key && now - cache.fetchedAt > REFETCH_COOLDOWN_MS) {
    cache = await loadKeys(teamDomain, fetchFn, now);
    key = cache.keys.get(kid);
  }
  if (!key) throw new AccessError("token was signed by an unknown key");
  return key;
}

export function readAssertion(request: Request): string | null {
  const header = request.headers.get("cf-access-jwt-assertion");
  return header && header.trim() !== "" ? header.trim() : null;
}

/**
 * Throws AccessError for anything but a valid, unexpired token issued by this team for `audience`.
 * `nowMs` and `fetchFn` are injectable for tests.
 */
export async function verifyAccessJwt(
  token: string,
  config: AccessConfig,
  audience: string,
  fetchFn: FetchLike = (url) => fetch(url),
  nowMs: number = Date.now(),
): Promise<Actor> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => p === "")) throw new AccessError("malformed token");
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  const header = decodeJson(headerPart);
  if (header["alg"] !== "RS256") throw new AccessError("unsupported signing algorithm");
  if (typeof header["kid"] !== "string") throw new AccessError("token has no key id");

  const payload = decodeJson(payloadPart);

  const key = await keyFor(header["kid"], config.teamDomain, fetchFn, nowMs);
  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64urlToBytes(signaturePart),
      new TextEncoder().encode(`${headerPart}.${payloadPart}`),
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new AccessError("bad signature");

  if (payload["iss"] !== `https://${config.teamDomain}`) throw new AccessError("wrong issuer");
  const aud = payload["aud"];
  const audiences = Array.isArray(aud) ? aud : typeof aud === "string" ? [aud] : [];
  if (!audiences.includes(audience)) throw new AccessError("wrong audience");

  const nowS = nowMs / 1000;
  const exp = payload["exp"];
  if (typeof exp !== "number" || exp + CLOCK_SKEW_SECONDS < nowS) throw new AccessError("token expired");
  const nbf = payload["nbf"];
  if (nbf !== undefined && (typeof nbf !== "number" || nbf - CLOCK_SKEW_SECONDS > nowS)) throw new AccessError("token not yet valid");

  const email = payload["email"];
  if (typeof email === "string" && email !== "") return { kind: "user", email };
  const clientId = payload["common_name"];
  if (typeof clientId === "string" && clientId !== "") return { kind: "service-token", clientId };
  throw new AccessError("token identifies neither a user nor a service token");
}

export const actorLabel = (actor: Actor): string => (actor.kind === "user" ? actor.email : `service-token:${actor.clientId}`);

import { resetJwksCache, type FetchLike } from "../src/access-jwt.js";

export const TEAM = "acme.cloudflareaccess.com";
export const AUD = "a".repeat(64);
export const OTHER_AUD = "b".repeat(64);
export const NOW_MS = 1_800_000_000_000;
export const NOW_S = NOW_MS / 1000;

const enc = new TextEncoder();
const b64url = (input: ArrayBuffer | Uint8Array | string): string => {
  const bytes = typeof input === "string" ? enc.encode(input) : new Uint8Array(input);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export interface TestKey {
  kid: string;
  privateKey: CryptoKey;
  jwk: JsonWebKey;
}

export async function makeKey(kid: string): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return { kid, privateKey: pair.privateKey, jwk };
}

export interface SignOptions {
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
}

export const goodPayload = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  iss: `https://${TEAM}`,
  aud: [AUD],
  exp: NOW_S + 3600,
  iat: NOW_S - 10,
  nbf: NOW_S - 10,
  email: "demo@example.com",
  ...over,
});

export async function sign(key: TestKey, options: SignOptions = {}): Promise<string> {
  const header = { alg: "RS256", kid: key.kid, typ: "JWT", ...options.header };
  const payload = options.payload ?? goodPayload();
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, enc.encode(signingInput));
  return `${signingInput}.${b64url(signature)}`;
}

export const jwks = (...keys: TestKey[]): Response =>
  Response.json({ keys: keys.map((k) => ({ ...k.jwk, kid: k.kid, kty: "RSA", alg: "RS256", use: "sig" })) });

export function fakeJwks(...keys: TestKey[]): { fetch: FetchLike; calls: () => number; serve: (...k: TestKey[]) => void } {
  let served = keys;
  let calls = 0;
  return {
    fetch: async (url) => {
      calls++;
      expectJwksUrl(url);
      return jwks(...served);
    },
    calls: () => calls,
    serve: (...k) => {
      served = k;
    },
  };
}

function expectJwksUrl(url: string): void {
  if (url !== `https://${TEAM}/cdn-cgi/access/certs`) throw new Error(`unexpected JWKS URL ${url}`);
}

export const reset = (): void => resetJwksCache();

export { b64url };

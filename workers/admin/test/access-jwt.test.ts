import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AccessError, actorLabel, readAssertion, verifyAccessJwt } from "../src/access-jwt.js";
import { AUD, OTHER_AUD, NOW_MS, NOW_S, TEAM, b64url, fakeJwks, goodPayload, makeKey, reset, sign, type TestKey } from "./jwt-helpers.js";

const config = { teamDomain: TEAM };
let key: TestKey;
let other: TestKey;

beforeAll(async () => {
  key = await makeKey("k1");
  other = await makeKey("k2");
});
beforeEach(reset);

const verify = (token: string, audience = AUD, fetchFn = fakeJwks(key).fetch, now = NOW_MS) =>
  verifyAccessJwt(token, config, audience, fetchFn, now);
const rejects = (promise: Promise<unknown>, message: RegExp) => expect(promise).rejects.toThrow(message);

describe("accepting valid tokens", () => {
  it("identifies a person by email", async () => {
    expect(await verify(await sign(key))).toEqual({ kind: "user", email: "demo@example.com" });
  });
  it("identifies a service token by common_name, which has no email", async () => {
    const token = await sign(key, { payload: goodPayload({ email: undefined, common_name: "abc123.access" }) });
    const actor = await verify(token, AUD);
    expect(actor).toEqual({ kind: "service-token", clientId: "abc123.access" });
    expect(actorLabel(actor)).toBe("service-token:abc123.access");
  });
  it("accepts aud given as a bare string", async () => {
    expect(await verify(await sign(key, { payload: goodPayload({ aud: AUD }) }))).toMatchObject({ kind: "user" });
  });
  it("accepts a token whose aud lists several applications", async () => {
    expect(await verify(await sign(key, { payload: goodPayload({ aud: ["x".repeat(64), AUD] }) }))).toMatchObject({ kind: "user" });
  });
  it("prefers email when both claims are present", async () => {
    const t = await sign(key, { payload: goodPayload({ common_name: "abc.access" }) });
    expect(await verify(t)).toEqual({ kind: "user", email: "demo@example.com" });
  });
});

describe("audience", () => {
  it("rejects a token issued for a different application", async () => {
    await rejects(verify(await sign(key), OTHER_AUD), /wrong audience/);
    const other = await sign(key, { payload: goodPayload({ aud: [OTHER_AUD] }) });
    await rejects(verify(other, AUD), /wrong audience/);
  });
  it("rejects a token with no aud at all", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ aud: undefined }) })), /wrong audience/);
  });
  it("rejects a non-string, non-array aud", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ aud: { x: AUD } }) })), /wrong audience/);
  });
});

describe("rejecting forged or invalid tokens", () => {
  it("rejects a token signed by a different key that claims a known kid", async () => {
    const forged = await sign({ ...other, kid: "k1" });
    await rejects(verify(forged), /bad signature/);
  });
  it("rejects a tampered payload", async () => {
    const [h, , s] = (await sign(key)).split(".");
    const evil = b64url(JSON.stringify(goodPayload({ email: "attacker@example.com" })));
    await rejects(verify(`${h}.${evil}.${s}`), /bad signature/);
  });
  it("rejects a tampered signature", async () => {
    const [h, p, s] = (await sign(key)).split(".");
    const flipped = (s as string).startsWith("A") ? `B${(s as string).slice(1)}` : `A${(s as string).slice(1)}`;
    await rejects(verify(`${h}.${p}.${flipped}`), /bad signature/);
  });
  it.each(["none", "HS256", "RS512", "ES256", ""])("rejects alg %j (algorithm confusion)", async (alg) => {
    await rejects(verify(await sign(key, { header: { alg } })), /unsupported signing algorithm/);
  });
  it("rejects alg none with an empty signature", async () => {
    const h = b64url(JSON.stringify({ alg: "none", kid: "k1" }));
    const p = b64url(JSON.stringify(goodPayload()));
    await rejects(verify(`${h}.${p}.`), /malformed token/);
  });
  it("rejects HS256 signed with the public key bytes as the secret", async () => {
    const h = b64url(JSON.stringify({ alg: "HS256", kid: "k1" }));
    const p = b64url(JSON.stringify(goodPayload()));
    await rejects(verify(`${h}.${p}.${b64url("not-a-real-mac")}`), /unsupported signing algorithm/);
  });
  it("rejects a token with no kid", async () => {
    await rejects(verify(await sign(key, { header: { kid: undefined } })), /no key id/);
  });
  it("rejects the wrong issuer", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ iss: "https://evil.cloudflareaccess.com" }) })), /wrong issuer/);
  });
  it("rejects an issuer that merely contains the team domain", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ iss: `https://${TEAM}.evil.com` }) })), /wrong issuer/);
  });
  it("rejects a token with neither email nor common_name", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ email: undefined }) })), /neither a user nor a service token/);
  });
  it("rejects empty-string identities", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ email: "", common_name: "" }) })), /neither/);
  });
  it.each(["", "a", "a.b", "a.b.c.d", "a..c", "..", "not a token"])("rejects malformed token %j", async (t) => {
    await expect(verify(t)).rejects.toBeInstanceOf(AccessError);
  });
  it("rejects a header or payload that is not a JSON object", async () => {
    const arr = b64url(JSON.stringify([1]));
    await rejects(verify(`${arr}.${arr}.${arr}`), /malformed token/);
    await rejects(verify(`!!!.!!!.!!!`), /malformed token/);
  });
});

describe("time", () => {
  it("rejects an expired token", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ exp: NOW_S - 60 }) })), /expired/);
  });
  it("tolerates 30 seconds of clock skew on exp, no more", async () => {
    expect(await verify(await sign(key, { payload: goodPayload({ exp: NOW_S - 29 }) }))).toBeTruthy();
    await rejects(verify(await sign(key, { payload: goodPayload({ exp: NOW_S - 31 }) })), /expired/);
  });
  it("rejects a token with no exp or a non-numeric exp", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ exp: undefined }) })), /expired/);
    await rejects(verify(await sign(key, { payload: goodPayload({ exp: "9999999999" }) })), /expired/);
  });
  it("rejects a token that is not valid yet, with 30 seconds of skew", async () => {
    expect(await verify(await sign(key, { payload: goodPayload({ nbf: NOW_S + 29 }) }))).toBeTruthy();
    await rejects(verify(await sign(key, { payload: goodPayload({ nbf: NOW_S + 31 }) })), /not yet valid/);
  });
  it("rejects a non-numeric nbf", async () => {
    await rejects(verify(await sign(key, { payload: goodPayload({ nbf: "soon" }) })), /not yet valid/);
  });
});

describe("the signing key set", () => {
  it("fetches once and caches", async () => {
    const jwks = fakeJwks(key);
    await verify(await sign(key), AUD, jwks.fetch);
    await verify(await sign(key), AUD, jwks.fetch);
    expect(jwks.calls()).toBe(1);
  });
  it("refetches after the cache expires", async () => {
    const jwks = fakeJwks(key);
    await verify(await sign(key), AUD, jwks.fetch, NOW_MS);
    await verify(await sign(key), AUD, jwks.fetch, NOW_MS + 11 * 60_000);
    expect(jwks.calls()).toBe(2);
  });
  it("picks up a rotated key: an unknown kid triggers a refetch", async () => {
    const jwks = fakeJwks(key);
    await verify(await sign(key), AUD, jwks.fetch, NOW_MS);
    jwks.serve(key, other);
    expect(await verify(await sign(other), AUD, jwks.fetch, NOW_MS + 60_000)).toBeTruthy();
    expect(jwks.calls()).toBe(2);
  });
  it("does not refetch for an unknown kid more often than the cooldown, so junk tokens cannot hammer Access", async () => {
    const jwks = fakeJwks(key);
    await verify(await sign(key), AUD, jwks.fetch, NOW_MS);
    for (let i = 0; i < 5; i++) await rejects(verify(await sign({ ...other, kid: `junk${i}` }), AUD, jwks.fetch, NOW_MS + 1000), /unknown key/);
    expect(jwks.calls()).toBe(1);
  });
  it("fails closed when the key set cannot be fetched", async () => {
    const boom = async () => {
      throw new Error("network down");
    };
    await rejects(verify(await sign(key), AUD, boom), /could not fetch/);
  });
  it.each([
    ["an HTTP error", () => new Response("no", { status: 503 }), /HTTP 503/],
    ["a non-JSON body", () => new Response("<html>"), /not JSON/],
    ["no key set", () => Response.json({}), /no key set/],
    ["an empty key set", () => Response.json({ keys: [] }), /no usable RSA key/],
    ["only non-RSA keys", () => Response.json({ keys: [{ kty: "EC", kid: "k1" }] }), /no usable RSA key/],
  ])("fails closed on %s", async (_n, make, message) => {
    await rejects(verify(await sign(key), AUD, async () => make()), message);
  });
  it("does not trust a stale cached key forever: a revoked key is dropped on refresh", async () => {
    const jwks = fakeJwks(key, other);
    await verify(await sign(other), AUD, jwks.fetch, NOW_MS);
    jwks.serve(key);
    await rejects(verify(await sign(other), AUD, jwks.fetch, NOW_MS + 11 * 60_000), /unknown key/);
  });
});

describe("readAssertion", () => {
  it("reads and trims the header, and treats absent or blank as null", () => {
    expect(readAssertion(new Request("https://x", { headers: { "cf-access-jwt-assertion": "  abc  " } }))).toBe("abc");
    expect(readAssertion(new Request("https://x"))).toBeNull();
    expect(readAssertion(new Request("https://x", { headers: { "cf-access-jwt-assertion": "   " } }))).toBeNull();
  });
});

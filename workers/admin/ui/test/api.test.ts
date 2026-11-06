import { describe, expect, it } from "vitest";
import { ApiError, getJson, type FetchFn } from "../src/api.js";

const respond = (body: unknown, init: ResponseInit = {}): FetchFn => async () => Response.json(body, init);
const opaqueRedirect = (): FetchFn => async () => ({ type: "opaqueredirect", status: 0, ok: false }) as unknown as Response;
const capture = () => {
  const seen: { url: string; init: RequestInit }[] = [];
  const fn: FetchFn = async (url, init) => {
    seen.push({ url, init });
    return Response.json({ ok: true });
  };
  return { fn, seen };
};
const fails = async (p: Promise<unknown>): Promise<ApiError> => (await p.catch((e: unknown) => e)) as ApiError;

describe("getJson", () => {
  it("returns the parsed body", async () => {
    expect(await getJson("/api/x", {}, undefined, respond({ a: 1 }))).toEqual({ a: 1 });
  });
  it("builds the query string, dropping empty and undefined values", async () => {
    const { fn, seen } = capture();
    await getJson("/api/x", { a: "1", b: "", c: undefined, d: "x y" }, undefined, fn);
    expect(seen[0]?.url).toBe("/api/x?a=1&d=x+y");
  });
  it("adds no query string when there are no params", async () => {
    const { fn, seen } = capture();
    await getJson("/api/x", { a: "" }, undefined, fn);
    expect(seen[0]?.url).toBe("/api/x");
  });
  it("never follows a redirect, so an Access login redirect can be detected", async () => {
    const { fn, seen } = capture();
    await getJson("/api/x", {}, undefined, fn);
    expect(seen[0]?.init.redirect).toBe("manual");
    expect(seen[0]?.init.credentials).toBe("same-origin");
  });
});

describe("session expiry", () => {
  it("treats an opaque redirect (Access sending the user to login) as a session problem", async () => {
    const err = await fails(getJson("/api/x", {}, undefined, opaqueRedirect()));
    expect(err).toBeInstanceOf(ApiError);
    expect(err.kind).toBe("session");
  });
  it.each([401, 403])("treats HTTP %d as a session problem", async (status) => {
    const err = await fails(getJson("/api/x", {}, undefined, respond({ error: "x" }, { status })));
    expect(err.kind).toBe("session");
    expect(err.status).toBe(status);
  });
});

describe("other failures", () => {
  it("uses the server's error message for an HTTP error", async () => {
    const err = await fails(getJson("/api/x", {}, undefined, respond({ error: "limit must be between 1 and 200" }, { status: 400 })));
    expect(err).toMatchObject({ kind: "http", status: 400, message: "limit must be between 1 and 200" });
  });
  it("falls back to a generic message when the error body is not JSON", async () => {
    const err = await fails(getJson("/api/x", {}, undefined, async () => new Response("<html>", { status: 502 })));
    expect(err).toMatchObject({ kind: "http", status: 502, message: "Request failed (502)" });
  });
  it("ignores a non-string error field", async () => {
    const err = await fails(getJson("/api/x", {}, undefined, respond({ error: { nested: 1 } }, { status: 500 })));
    expect(err.message).toBe("Request failed (500)");
  });
  it("reports an unreadable success body rather than crashing", async () => {
    const err = await fails(getJson("/api/x", {}, undefined, async () => new Response("not json", { status: 200 })));
    expect(err).toMatchObject({ kind: "http", message: "The server sent an unreadable response" });
  });
  it("reports a network failure", async () => {
    const err = await fails(
      getJson("/api/x", {}, undefined, async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    expect(err).toMatchObject({ kind: "network", message: "Could not reach the server" });
  });
  it("lets an abort through untouched so callers can ignore it", async () => {
    const abort = new DOMException("aborted", "AbortError");
    const err = (await getJson("/api/x", {}, undefined, async () => {
      throw abort;
    }).catch((e: unknown) => e)) as unknown;
    expect(err).toBe(abort);
  });
});

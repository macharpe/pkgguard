import { describe, expect, it } from "vitest";
import { ApiError, CSRF_HEADER, getJson, postJson, type FetchFn } from "../src/api.js";

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

describe("postJson", () => {
  it("sends a POST with the CSRF header, no redirect-following and same-origin credentials", async () => {
    const { fn, seen } = capture();
    await postJson("/api/refresh", undefined, fn);
    expect(seen[0]?.url).toBe("/api/refresh");
    expect(seen[0]?.init.method).toBe("POST");
    expect((seen[0]?.init.headers as Record<string, string>)[CSRF_HEADER]).toBe("1");
    expect(seen[0]?.init.redirect).toBe("manual");
    expect(seen[0]?.init.credentials).toBe("same-origin");
  });
  it("never sends the CSRF header on a read", async () => {
    const { fn, seen } = capture();
    await getJson("/api/x", {}, undefined, fn);
    expect((seen[0]?.init.headers as Record<string, string>)[CSRF_HEADER]).toBeUndefined();
    expect(seen[0]?.init.method).toBe("GET");
  });
  it("returns the parsed body", async () => {
    expect(await postJson("/api/refresh", undefined, respond({ runId: "abc" }, { status: 202 }))).toEqual({ runId: "abc" });
  });
  it("carries the JSON body of a 409, so the caller can follow the run already in progress", async () => {
    const err = await fails(postJson("/api/refresh", undefined, respond({ error: "a refresh is already running", runId: "run-9" }, { status: 409 })));
    expect(err).toMatchObject({ kind: "http", status: 409, message: "a refresh is already running", body: { runId: "run-9" } });
  });
  it("does not call a 403 on a write a session problem: it can be the CSRF guard, and Sign in would not help", async () => {
    const err = await fails(postJson("/api/refresh", undefined, respond({ error: "missing CSRF header" }, { status: 403 })));
    expect(err).toMatchObject({ kind: "http", status: 403, message: "missing CSRF header" });
  });
  it("still treats an opaque redirect and a 401 on a write as an ended session", async () => {
    expect((await fails(postJson("/api/refresh", undefined, opaqueRedirect()))).kind).toBe("session");
    expect((await fails(postJson("/api/refresh", undefined, respond({}, { status: 401 })))).kind).toBe("session");
  });
  it("reports a network failure", async () => {
    const err = await fails(postJson("/api/refresh", undefined, async () => { throw new TypeError("Failed to fetch"); }));
    expect(err.kind).toBe("network");
  });
});

describe("error bodies", () => {
  it("is undefined when the body is not JSON, and when it is not an object", async () => {
    expect((await fails(getJson("/api/x", {}, undefined, async () => new Response("<html>", { status: 502 })))).body).toBeUndefined();
    expect((await fails(getJson("/api/x", {}, undefined, respond([1, 2], { status: 500 })))).body).toBeUndefined();
  });
});

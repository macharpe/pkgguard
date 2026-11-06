import { env } from "cloudflare:test";
import { MALWARE_ALERT_TTL_SECONDS, malwareAlertKey, type MalwareAlert, type OsvRecord } from "@pkgguard/core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import eventStreamJson from "../../../packages/core/test/fixtures/GHSA-mh6f-8j2x-4483.json";
import lodashJson from "../../../packages/core/test/fixtures/GHSA-35jh-r3h4-6jhm.json";
import { maybeAlertMalware, type AlertDeps } from "../src/alert.js";
import { detections, reset, run, seed, tarball } from "./harness.js";

const HOOK = "https://chat.googleapis.com/v1/spaces/AAAAbcd/messages?key=KEY&token=TOKEN";
const eventStream = eventStreamJson as unknown as OsvRecord;
const lodashCve = lodashJson as unknown as OsvRecord;

const sample: MalwareAlert = { ecosystem: "npm", name: "event-stream", version: "3.3.6", user: "dev@example.com", blocked: true, reason: "osv-malware", osvIds: ["GHSA-mh6f-8j2x-4483"] };

interface Posted {
  url: string;
  text: string;
}
/** Records posts to the webhook; every other fetch gets an empty OSV answer. */
function chat(status = 200) {
  const posted: Posted[] = [];
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("https://chat.googleapis.com/")) {
      posted.push({ url, text: (JSON.parse(String(init?.body)) as { text: string }).text });
      return new Response("{}", { status });
    }
    return new Response("{}", { status: 200 });
  });
  return { posted, spy };
}
const settle = () => new Promise((r) => setTimeout(r, 20));

beforeEach(reset);
afterEach(() => vi.restoreAllMocks());

describe("maybeAlertMalware", () => {
  const deps = (over: Partial<AlertDeps> = {}): AlertDeps => ({ kv: env.PKG_INDEX, fetch: (u, i) => fetch(u, i), webhook: HOOK, ...over });

  it("skips without touching KV or the network when no webhook is configured", async () => {
    const { posted } = chat();
    const kv = { get: vi.fn(), put: vi.fn() };
    expect(await maybeAlertMalware(deps({ webhook: undefined, kv }), sample)).toBe("skipped");
    expect(await maybeAlertMalware(deps({ webhook: "", kv }), sample)).toBe("skipped");
    expect(kv.get).not.toHaveBeenCalled();
    expect(posted).toEqual([]);
  });
  it("sends the first alert and remembers it for an hour", async () => {
    const { posted } = chat();
    const put = vi.spyOn(env.PKG_INDEX, "put");
    expect(await maybeAlertMalware(deps(), sample)).toBe("sent");
    expect(posted).toHaveLength(1);
    expect(posted[0]?.url).toBe(HOOK);
    expect(posted[0]?.text).toContain("`event-stream@3.3.6`");
    expect(put).toHaveBeenCalledWith(malwareAlertKey("npm", "event-stream"), "1", { expirationTtl: MALWARE_ALERT_TTL_SECONDS });
  });
  it("sends only one alert per package per hour, whatever the version", async () => {
    const { posted } = chat();
    expect(await maybeAlertMalware(deps(), sample)).toBe("sent");
    expect(await maybeAlertMalware(deps(), sample)).toBe("rate-limited");
    expect(await maybeAlertMalware(deps(), { ...sample, version: "3.3.7" })).toBe("rate-limited");
    expect(await maybeAlertMalware(deps(), { ...sample, name: "Event-Stream" })).toBe("rate-limited");
    expect(posted).toHaveLength(1);
  });
  it("alerts separately for another package and for the same name in another ecosystem", async () => {
    const { posted } = chat();
    await maybeAlertMalware(deps(), sample);
    expect(await maybeAlertMalware(deps(), { ...sample, name: "flatmap-stream" })).toBe("sent");
    expect(await maybeAlertMalware(deps(), { ...sample, ecosystem: "pypi" })).toBe("sent");
    expect(posted).toHaveLength(3);
  });
  it("retries within a minute, not an hour, when Chat rejects the message", async () => {
    chat(500);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const put = vi.spyOn(env.PKG_INDEX, "put");
    expect(await maybeAlertMalware(deps(), sample)).toBe("failed");
    expect(put).toHaveBeenLastCalledWith(malwareAlertKey("npm", "event-stream"), "1", { expirationTtl: 60 });
  });
  it("does nothing, and posts nothing, when the rate-limit store cannot be read", async () => {
    const { posted } = chat();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const kv = { get: async () => { throw new Error("KV down"); }, put: vi.fn() };
    expect(await maybeAlertMalware(deps({ kv: kv as never }), sample)).toBe("skipped");
    expect(posted).toEqual([]);
  });
  it("does nothing when the rate-limit store cannot be written, rather than risk flooding", async () => {
    const { posted } = chat();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const kv = { get: async () => null, put: async () => { throw new Error("KV down"); } };
    expect(await maybeAlertMalware(deps({ kv: kv as never }), sample)).toBe("skipped");
    expect(posted).toEqual([]);
  });
  it("refuses a webhook that is not a Chat URL", async () => {
    const { posted } = chat();
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await maybeAlertMalware(deps({ webhook: "https://evil.example.com/steal" }), sample)).toBe("failed");
    expect(posted).toEqual([]);
  });
});

describe("the filter and its malware alerts", () => {
  const withHook = { GCHAT_WEBHOOK: HOOK };
  beforeEach(async () => {
    await seed(eventStream, "npm", "event-stream");
    await seed(lodashCve, "npm", "lodash");
  });

  it("alerts when malware is observed with enforcement off, and the download still goes through", async () => {
    const { posted } = chat();
    const { response, next, upstream } = await run(tarball("event-stream", "3.3.6"), { env: withHook });
    await settle();
    expect(response).toBe(upstream);
    expect(next).toHaveBeenCalledOnce();
    expect(posted).toHaveLength(1);
    expect(posted[0]?.text).toContain("observed, not blocked");
    expect(posted[0]?.text).toContain("`dev@example.com`");
    expect(posted[0]?.text).toContain("GHSA-mh6f-8j2x-4483");
  });
  it("alerts that it was blocked when enforcing, and the user gets the coaching page", async () => {
    const { posted } = chat();
    const { response, next } = await run(tarball("event-stream", "3.3.6"), { env: { ...withHook, ENFORCE: "true" } });
    await settle();
    expect(response.status).toBe(403);
    expect(next).not.toHaveBeenCalled();
    expect(posted).toHaveLength(1);
    expect(posted[0]?.text).toContain("*blocked*");
    expect(posted[0]?.text).not.toContain("not blocked");
  });
  it("sends one alert for repeated downloads of the same package", async () => {
    const { posted } = chat();
    for (let i = 0; i < 4; i++) {
      await run(tarball("event-stream", "3.3.6"), { env: withHook });
      await settle();
    }
    expect(posted).toHaveLength(1);
    expect(await detections()).toHaveLength(4);
  });
  it("does not alert for a vulnerability, which is only logged", async () => {
    const { posted } = chat();
    await run(tarball("lodash", "4.17.20"), { env: withHook });
    await settle();
    expect(posted).toEqual([]);
    expect((await detections())[0]).toMatchObject({ verdict: "flagged", reason: "osv-cve" });
  });
  it("does not alert for a clean package", async () => {
    const { posted } = chat();
    await run(tarball("left-pad", "1.3.0"), { env: withHook });
    await settle();
    expect(posted).toEqual([]);
  });
  it("does not alert when the malicious version is not the one downloaded", async () => {
    const { posted } = chat();
    await run(tarball("event-stream", "4.0.1"), { env: withHook });
    await settle();
    expect(posted).toEqual([]);
  });
  it("alerts for a package on the block list, saying so", async () => {
    await env.PKG_INDEX.put("override:block:npm:left-pad", JSON.stringify({ v: 1, versions: null }));
    const { posted } = chat();
    await run(tarball("left-pad", "1.3.0"), { env: { ...withHook, ENFORCE: "true" } });
    await settle();
    expect(posted).toHaveLength(1);
    expect(posted[0]?.text).toContain("on the block list");
  });
  it("does not alert for an allow override, even on a package with malware advisories", async () => {
    await env.PKG_INDEX.put("override:allow:npm:event-stream", JSON.stringify({ v: 1, versions: null }));
    const { posted } = chat();
    await run(tarball("event-stream", "3.3.6"), { env: withHook });
    await settle();
    expect(posted).toEqual([]);
  });
  it("never sends anything to Chat when no webhook is configured", async () => {
    const { spy } = chat();
    await run(tarball("event-stream", "3.3.6"), {});
    await settle();
    expect(spy.mock.calls.some(([u]) => String(u).includes("chat.googleapis.com"))).toBe(false);
  });
  it("is unaffected by a failing webhook: same decision, same detection, same response", async () => {
    chat(500);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { response, next, upstream } = await run(tarball("event-stream", "3.3.6"), { env: withHook });
    await settle();
    expect(response).toBe(upstream);
    expect(next).toHaveBeenCalledOnce();
    expect(await detections()).toEqual([expect.objectContaining({ verdict: "flagged", reason: "osv-malware" })]);
  });
  it("is unaffected by a webhook that is not a Chat URL", async () => {
    const { posted } = chat();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const { response, upstream } = await run(tarball("event-stream", "3.3.6"), { env: { GCHAT_WEBHOOK: "https://evil.example.com/steal" } });
    await settle();
    expect(response).toBe(upstream);
    expect(posted).toEqual([]);
  });
});

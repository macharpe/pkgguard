import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { beforeEach, describe, expect, it } from "vitest";
import type { OsvRecord } from "@pkgguard/core";
import eventStreamJson from "../../../packages/core/test/fixtures/GHSA-mh6f-8j2x-4483.json";
import { detections, gatewayContext, reset, seed, tarball } from "./harness.js";

// Gateway reaches the Worker as `GatewayMiddleware.handle` over RPC, with `next` and the
// context's methods arriving as stubs. Calling the class directly would not prove any of that.
interface Middleware {
  handle(request: Request, context: unknown, next: (r: Request) => Promise<Response>): Promise<Response>;
}
const middleware = (): Middleware => (exports as unknown as { GatewayMiddleware: Middleware }).GatewayMiddleware;

beforeEach(reset);

describe("GatewayMiddleware over RPC", () => {
  it("is exported under exactly that name", () => {
    expect(Object.keys(exports)).toContain("GatewayMiddleware");
  });

  it("passes a clean download through to next() and returns its response", async () => {
    let seen: string | undefined;
    const response = await middleware().handle(new Request(tarball("left-pad", "1.3.0")), gatewayContext(), async (r) => {
      seen = r.url;
      return new Response("upstream-bytes");
    });
    expect(await response.text()).toBe("upstream-bytes");
    expect(seen).toBe(tarball("left-pad", "1.3.0"));
  });

  it("under the shipped ENFORCE=false, flags malware, still calls next() once, and resolves identity through its stub", async () => {
    await seed(eventStreamJson as unknown as OsvRecord, "npm", "event-stream");
    let called = 0;
    const response = await middleware().handle(
      new Request(tarball("event-stream", "3.3.6")),
      gatewayContext(async () => ({ email: "rpc@example.com" })),
      async () => {
        called++;
        return new Response("upstream");
      },
    );
    expect(env.ENFORCE).toBe("false");
    expect(response.status).toBe(200);
    expect(called).toBe(1);
    // waitUntil work finishes after the RPC call returns, so poll instead of assuming it already has.
    for (let i = 0; i < 40 && (await detections()).length === 0; i++) await new Promise((r) => setTimeout(r, 50));
    expect((await detections())[0]).toMatchObject({ verdict: "flagged", user_email: "rpc@example.com" });
  });
});

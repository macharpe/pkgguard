import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { adminEnv, call, setup, user } from "./harness.js";
import { AUD_UI } from "./jwt-helpers.js";

/**
 * Runs against the real Assets binding, so it only means something once the dashboard is built.
 * `npm run deploy:admin` always builds first; locally run `npm run build:admin`.
 */
beforeEach(setup);

describe("the real Assets binding", () => {
  it("serves the built dashboard through the Worker", async (ctx) => {
    if ((await env.ASSETS.fetch(new Request("https://x.example/"))).status !== 200) ctx.skip();
    const e = adminEnv({ ASSETS: env.ASSETS });
    const token = await user(AUD_UI);

    const page = await call("/", token, {}, e);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-type")).toMatch(/text\/html/);
    const html = await page.text();
    expect(html).toContain('<div id="root">');
    expect(html).toContain('src="/theme-init.js"');
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/); // no inline script, or the CSP would block it

    const bundle = /src="(\/assets\/[^"]+\.js)"/.exec(html)?.[1];
    expect(bundle, "the built page references a hashed bundle").toBeTruthy();
    const js = await call(bundle as string, token, {}, e);
    expect(js.status).toBe(200);
    expect(js.headers.get("cache-control")).toBe("private, max-age=31536000, immutable");

    expect((await call("/theme-init.js", token, {}, e)).status).toBe(200);
    expect((await call("/index.html", token, {}, e)).status).toBe(200);
  });

  it("answers a missing asset with the JSON 404, not an asset body", async (ctx) => {
    if ((await env.ASSETS.fetch(new Request("https://x.example/"))).status !== 200) ctx.skip();
    const r = await call("/assets/does-not-exist.js", await user(AUD_UI), {}, adminEnv({ ASSETS: env.ASSETS }));
    expect(r.status).toBe(404);
    expect(await r.json()).toEqual({ error: "not found" });
  });
});

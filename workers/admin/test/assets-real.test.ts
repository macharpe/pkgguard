import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { adminEnv, call, setup, user } from "./harness.js";
import { AUD } from "./jwt-helpers.js";

/**
 * Runs against the real Assets binding, so it only means something once the dashboard is built.
 * `npm run deploy:admin` always builds first; locally run `npm run build:admin`.
 */
beforeEach(setup);

describe("the real Assets binding", () => {
  it("serves the built dashboard through the Worker", async (ctx) => {
    if ((await env.ASSETS.fetch(new Request("https://x.example/"))).status !== 200) ctx.skip();
    const e = adminEnv({ ASSETS: env.ASSETS });
    const token = await user(AUD);

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

  it("serves every icon the page links, as the right type, behind the JWT", async (ctx) => {
    if ((await env.ASSETS.fetch(new Request("https://x.example/"))).status !== 200) ctx.skip();
    const e = adminEnv({ ASSETS: env.ASSETS });
    const token = await user(AUD);
    const html = await (await call("/", token, {}, e)).text();

    const links = [...html.matchAll(/<link\s+rel="(icon|apple-touch-icon)"[^>]*>/g)].map((m) => ({
      rel: m[1],
      href: /href="([^"]+)"/.exec(m[0])?.[1] ?? "",
      type: /type="([^"]+)"/.exec(m[0])?.[1],
    }));
    expect(links.map((l) => l.href).sort()).toEqual(["/apple-touch-icon.png", "/favicon-32.png", "/favicon.svg"]);

    const pngSize = (bytes: Uint8Array): [number, number] => {
      const view = new DataView(bytes.buffer, bytes.byteOffset);
      expect([...bytes.slice(0, 8)], "PNG signature").toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      return [view.getUint32(16), view.getUint32(20)];
    };
    for (const { href, type } of links) {
      const r = await call(href, token, {}, e);
      expect(r.status, href).toBe(200);
      expect(r.headers.get("cache-control"), href).toBe("no-store");
      expect(r.headers.get("x-content-type-options"), href).toBe("nosniff");
      const bytes = new Uint8Array(await r.arrayBuffer());
      expect(bytes.length, href).toBeGreaterThan(200);
      if (href.endsWith(".svg")) {
        expect(type).toBe("image/svg+xml");
        expect(r.headers.get("content-type"), href).toMatch(/^image\/svg\+xml/);
        const svg = new TextDecoder().decode(bytes);
        expect(svg, "an SVG with a viewBox, so it scales").toMatch(/<svg[^>]*viewBox=/);
        expect(svg, "the glyph flips to a light fill on a dark tab bar").toContain("prefers-color-scheme:dark");
        expect(svg, "no script in an image that is served from the dashboard origin").not.toMatch(/<script|onload=|javascript:/i);
      } else {
        expect(r.headers.get("content-type"), href).toBe("image/png");
        expect(pngSize(bytes), href).toEqual(href.includes("apple-touch") ? [180, 180] : [32, 32]);
      }
    }
    expect(html, "the blank placeholder icon is gone").not.toContain('href="data:,"');
  });

  it("answers a missing asset with the JSON 404, not an asset body", async (ctx) => {
    if ((await env.ASSETS.fetch(new Request("https://x.example/"))).status !== 200) ctx.skip();
    const r = await call("/assets/does-not-exist.js", await user(AUD), {}, adminEnv({ ASSETS: env.ASSETS }));
    expect(r.status).toBe(404);
    expect(await r.json()).toEqual({ error: "not found" });
  });
});

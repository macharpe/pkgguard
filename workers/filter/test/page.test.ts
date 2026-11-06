import { describe, expect, it } from "vitest";
import type { Decision } from "../src/decide.js";
import { blockPage } from "../src/page.js";

const decision = (over: Partial<Decision> = {}): Decision => ({
  block: true,
  verdict: "blocked",
  reason: "osv-malware",
  osvIds: ["MAL-2026-1"],
  source: "index",
  ...over,
});

describe("blockPage", () => {
  it("escapes attacker-influenced strings", async () => {
    const response = blockPage(
      { ecosystem: "npm", namespace: "@<b>", name: '"><script>alert(1)</script>', version: "1.0.0" },
      decision({ osvIds: ["<img src=x onerror=alert(1)>"] }),
    );
    const html = await response.text();
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>");
    expect(html).toContain("&lt;script&gt;");
  });
  it("URL-encodes the advisory ID in the link", async () => {
    const html = await blockPage(
      { ecosystem: "npm", namespace: null, name: "x", version: "1.0.0" },
      decision({ osvIds: ["a b/c"] }),
    ).text();
    expect(html).toContain("https://osv.dev/vulnerability/a%20b%2Fc");
  });
  it("is a small self-contained 403", async () => {
    const response = blockPage({ ecosystem: "npm", namespace: null, name: "x", version: "1.0.0" }, decision());
    const html = await response.text();
    expect(response.status).toBe(403);
    expect(html.length).toBeLessThan(3000);
    expect(html).not.toMatch(/<(link|script|img)\b|src=|url\(/i);
  });
});

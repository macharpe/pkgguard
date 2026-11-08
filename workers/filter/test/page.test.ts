import { describe, expect, it } from "vitest";
import type { Decision } from "../src/decide.js";
import { blockResponse, clientKind, reasonPhrase } from "../src/page.js";

const decision = (over: Partial<Decision> = {}): Decision => ({
  block: true,
  verdict: "blocked",
  reason: "osv-malware",
  osvIds: ["GHSA-mh6f-8j2x-4483"],
  source: "index",
  ...over,
});
const pkg = { ecosystem: "npm" as const, namespace: null, name: "event-stream", version: "3.3.6" };
const REF = "PG-7Q2K4M";
const req = (headers: Record<string, string> = {}) => ({ headers: new Headers(headers) });
const BROWSER = { accept: "text/html,application/xhtml+xml,*/*;q=0.8", "user-agent": "Mozilla/5.0" };
const NPM = { accept: "*/*", "user-agent": "npm/11.18.0 node/v24.18.0 darwin arm64 workspaces/false" };
const PIP = { accept: "*/*", "user-agent": 'pip/26.2.2 {"installer":{"name":"pip"}}' };

describe("clientKind", () => {
  it("sends a browser the page, whatever its User-Agent says", () => {
    expect(clientKind(req(BROWSER))).toBe("browser");
    expect(clientKind(req({ accept: "TEXT/HTML", "user-agent": "npm/10" }))).toBe("browser");
  });
  it.each(["npm/11.18.0 node/v24 darwin arm64", "pnpm/9.1.0 npm/? node/v22", "yarn/1.22.19 npm/? node/v20", "bun/1.1.0", "Bun/1.1.0", "NPM/10"])(
    "recognises %s as a package manager that prints a JSON error",
    (ua) => expect(clientKind(req({ accept: "*/*", "user-agent": ua }))).toBe("json"),
  );
  it.each([PIP["user-agent"], "curl/8.23.0", "Wget/1.21", "python-requests/2.31", "", "my-npm/1.0", "xnpm/1"])(
    "treats %j as plain text",
    (ua) => expect(clientKind(req({ accept: "*/*", "user-agent": ua }))).toBe("plain"),
  );
  it("copes with no headers at all", () => expect(clientKind(req())).toBe("plain"));
});

describe("reasonPhrase", () => {
  const f = { subject: "event-stream@3.3.6", short: "listed as malware", reference: REF };
  it("carries the package, the reason and the reference, because npm and pip print only this", () => {
    expect(reasonPhrase(f)).toBe("Blocked by PkgGuard: event-stream@3.3.6 is listed as malware. Ref PG-7Q2K4M");
  });
  it("omits the reference when there is none", () => {
    expect(reasonPhrase({ ...f, reference: null })).toBe("Blocked by PkgGuard: event-stream@3.3.6 is listed as malware");
  });
  it("is visible ASCII on one line, so it can never inject a header", () => {
    const out = reasonPhrase({ ...f, subject: "a\r\nX-Evil: 1\u0000é日", reference: null });
    expect(out).toMatch(/^[\x20-\x7e]+$/);
    expect(out).not.toMatch(/[\r\n]/);
  });
  it("never produces anything but visible ASCII, even from tabs and runs of spaces", () => {
    expect(reasonPhrase({ ...f, subject: "a\tb" })).toBe("Blocked by PkgGuard: a?b is listed as malware. Ref PG-7Q2K4M");
  });
  it("is bounded", () => {
    expect(reasonPhrase({ ...f, subject: "x".repeat(900) }).length).toBeLessThanOrEqual(160);
  });
});

describe("blockResponse: what each client receives", () => {
  it("answers every client with 403, uncacheable, with the reference and verdict as headers", () => {
    for (const h of [BROWSER, NPM, PIP, {}]) {
      const r = blockResponse(req(h), pkg, decision(), REF);
      expect(r.status).toBe(403);
      expect(r.headers.get("cache-control")).toBe("no-store");
      expect(r.headers.get("x-pkgguard-verdict")).toBe("blocked");
      expect(r.headers.get("x-pkgguard-reference")).toBe(REF);
      expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    }
  });
  it("puts the essentials in the reason phrase for every client", () => {
    for (const h of [BROWSER, NPM, PIP, {}]) {
      expect(blockResponse(req(h), pkg, decision(), REF).statusText).toBe("Blocked by PkgGuard: event-stream@3.3.6 is listed as malware. Ref PG-7Q2K4M");
    }
  });
  it("says it was an administrator, not OSV, for an override", () => {
    const r = blockResponse(req(PIP), pkg, decision({ reason: "override", osvIds: [] }), REF);
    expect(r.statusText).toContain("blocked by an administrator");
  });
  it("omits the reference header and text when there is no reference", async () => {
    const r = blockResponse(req(PIP), pkg, decision(), null);
    expect(r.headers.get("x-pkgguard-reference")).toBeNull();
    expect(r.statusText).not.toContain("Ref");
    expect(await r.text()).not.toContain("Reference");
  });

  describe("plain text (curl, pip, anything unknown)", () => {
    it("is a readable summary with the advisory link and the reference", async () => {
      const r = blockResponse(req(PIP), pkg, decision(), REF);
      expect(r.headers.get("content-type")).toBe("text/plain; charset=utf-8");
      const text = await r.text();
      expect(text).toContain("PkgGuard blocked this download.");
      expect(text).toContain("Package:   event-stream@3.3.6 (npm)");
      expect(text).toContain("https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483");
      expect(text).toContain("Reference: PG-7Q2K4M");
      expect(text).toContain("Do not install it another way");
      expect(text).toContain("Need it anyway? Ask in the PkgGuard space in Google Chat and quote PG-7Q2K4M.");
    });
    it("labels PyPI packages", async () => {
      const text = await blockResponse(req(PIP), { ...pkg, ecosystem: "pypi", name: "requests" }, decision(), REF).text();
      expect(text).toContain("requests@3.3.6 (PyPI)");
    });
    it("lines the values up and lists several advisories under one label", async () => {
      const text = await blockResponse(req(PIP), pkg, decision({ osvIds: ["A-1", "A-2"] }), REF).text();
      const lines = text.split("\n").filter((l) => l.startsWith("  "));
      const columns = lines.map((l) => (l.includes("https://") ? l.indexOf("https://") : l.includes("event-stream") ? l.indexOf("event-stream") : l.includes("PG-") ? l.indexOf("PG-") : l.indexOf("Listed") >= 0 ? l.indexOf("Listed") : l.indexOf("This")));
      expect(new Set(columns).size, JSON.stringify(columns)).toBe(1);
      expect(lines.filter((l) => l.includes("Advisory:"))).toHaveLength(1);
      expect(text).toContain("https://osv.dev/vulnerability/A-2");
    });
    it("uses the configured contact", async () => {
      const text = await blockResponse(req(PIP), pkg, decision(), REF, "#security-help").text();
      expect(text).toContain("Ask in #security-help and quote PG-7Q2K4M.");
    });
    it("neutralises markup in the contact and keeps the JSON error on one line", async () => {
      const r = blockResponse(req(NPM), pkg, decision(), REF, "line one\nline two\r\n<b>three</b>");
      const { error } = (await r.json()) as { error: string };
      expect(error).not.toMatch(/[\r\n<>]/);
      expect(error).toContain("Ask in line one line two b three /b and quote");
    });
    it("falls back to the default contact when the configured one is blank or only markup", async () => {
      for (const c of [undefined, "", "   ", "<>"]) {
        expect(await blockResponse(req(PIP), pkg, decision(), REF, c).text()).toContain("the PkgGuard space in Google Chat");
      }
    });
  });

  describe("JSON (npm and friends)", () => {
    it("is JSON whose `error` is the only part npm prints: why, the advisory and where to get help", async () => {
      const r = blockResponse(req(NPM), pkg, decision(), REF);
      expect(r.headers.get("content-type")).toBe("application/json; charset=utf-8");
      const body = (await r.json()) as Record<string, unknown>;
      expect(body["error"]).toBe(
        "Blocked by PkgGuard: listed as malware. Advisory https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483. Need it anyway? Ask in the PkgGuard space in Google Chat and quote PG-7Q2K4M.",
      );
      expect(String(body["error"])).not.toMatch(/[\r\n]/);
    });
    it("carries the full detail as fields", async () => {
      const body = (await blockResponse(req(NPM), pkg, decision(), REF).json()) as Record<string, unknown>;
      expect(body).toMatchObject({ blocked: true, reference: REF, package: "event-stream@3.3.6", ecosystem: "npm", advisories: ["https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483"] });
    });
    it("still has an error line when there is no advisory and no reference", async () => {
      const body = (await blockResponse(req(NPM), pkg, decision({ reason: "override", osvIds: [] }), null).json()) as { error: string };
      expect(body.error).toBe("Blocked by PkgGuard: blocked by an administrator. Need it anyway? Ask in the PkgGuard space in Google Chat.");
    });
  });

  describe("HTML (browsers)", () => {
    const page = async (over: Parameters<typeof decision>[0] = {}, ref: string | null = REF) => blockResponse(req(BROWSER), pkg, decision(over), ref).text();
    it("is a self-contained page: no script, no external resource, a closed Content-Security-Policy", async () => {
      const r = blockResponse(req(BROWSER), pkg, decision(), REF);
      const html = await r.text();
      expect(r.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(html).not.toMatch(/<(link|script|img|iframe|object|embed)\b|\bsrc=|url\(|@import/i);
      expect(html.length).toBeLessThan(8000);
      const csp = r.headers.get("content-security-policy") ?? "";
      expect(csp).toContain("default-src 'none'");
      expect(csp).not.toMatch(/script-src|unsafe-eval|https?:/);
      expect(r.headers.get("referrer-policy")).toBe("no-referrer");
    });
    it("shows the package, the reason, the advisory and the reference", async () => {
      const html = await page();
      expect(html).toContain("This package was blocked");
      expect(html).toContain("<code>event-stream@3.3.6</code>");
      expect(html).toContain("listed as malware in the OSV database");
      expect(html).toContain("not a warning about an outdated dependency");
      expect(html).toContain('href="https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483"');
      expect(html).toContain('<span class="ref">PG-7Q2K4M</span>');
      expect(html).toContain("quote this reference");
    });
    it("says an administrator did it for an override, without the malware wording", async () => {
      const html = await page({ reason: "override", osvIds: [] });
      expect(html).toContain("An administrator has blocked this package.");
      expect(html).not.toContain("outdated dependency");
      expect(html).not.toContain("<h2>Advisory</h2>");
    });
    it("leaves out the reference block when there is none", async () => {
      const html = await page({}, null);
      expect(html).not.toContain('class="ref"');
      expect(html).not.toContain("quote this reference");
    });
    it("escapes ampersands and quotes in the contact, which the text sanitiser leaves alone", async () => {
      const html = await blockResponse(req(BROWSER), pkg, decision(), REF, `Tom & "Jerry's" desk`).text();
      expect(html).toContain("Ask in Tom &amp; &quot;Jerry&#39;s&quot; desk");
      expect(html).not.toContain('Tom & "');
    });
    it("shows no reference at all when it does not have the real shape, so markup cannot ride in on it", async () => {
      for (const bad of ["<b>x</b>", 'PG-"><script>', "free text", "pg-7q2k4m"]) {
        const r = blockResponse(req(BROWSER), pkg, decision(), bad);
        const html = await r.text();
        expect(html, bad).not.toContain('class="ref"');
        expect(html, bad).not.toContain(bad);
        expect(r.headers.get("x-pkgguard-reference"), bad).toBeNull();
        expect(r.statusText, bad).not.toContain("Ref");
      }
    });
    it("adapts to the colour scheme and to narrow screens", async () => {
      const html = await page();
      expect(html).toContain("@media(prefers-color-scheme:light){");
      expect(html).toContain('name="viewport"');
      expect(html).toContain('<html lang="en">');
    });
    it("does not let a search engine keep it", async () => {
      expect(await page()).toContain('name="robots" content="noindex"');
    });
    it("escapes attacker-influenced strings", async () => {
      const html = await blockResponse(
        req(BROWSER),
        { ecosystem: "npm", namespace: "@<b>", name: '"><script>alert(1)</script>', version: "1.0.0" },
        decision({ osvIds: ["<img src=x onerror=alert(1)>"] }),
        REF,
        '<script>alert("x")</script>',
      ).text();
      expect(html).not.toMatch(/<script|<img|<b>/i);
      expect(html).not.toContain("onerror=alert(1)>");
    });
    it("URL-encodes the advisory ID in the link", async () => {
      expect(await page({ osvIds: ["a b/c"] })).toContain("https://osv.dev/vulnerability/a%20b%2Fc");
    });
    it("caps the advisories shown", async () => {
      const html = await page({ osvIds: Array.from({ length: 9 }, (_, i) => `ID-${i}`) });
      expect((html.match(/<li>/g) ?? []).length).toBe(5);
    });
  });

  it("cannot be used to inject a header through a hostile package name or version", () => {
    for (const h of [BROWSER, NPM, PIP]) {
      const r = blockResponse(req(h), { ecosystem: "npm", namespace: null, name: "a\r\nSet-Cookie: x=1", version: "1\r\n2" }, decision(), REF);
      expect(r.headers.get("set-cookie")).toBeNull();
      expect(r.statusText).toMatch(/^[\x20-\x7e]+$/);
    }
  });
});

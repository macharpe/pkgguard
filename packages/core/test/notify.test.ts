import { afterEach, describe, expect, it, vi } from "vitest";
import { isValidWebhook, malwareAlertKey, malwareMessage, overrideMessage, refreshMessage, safeText, safeToken, sendChat, type FetchLike } from "../src/notify.js";

const HOOK = "https://chat.googleapis.com/v1/spaces/AAAAbcd-123_x/messages?key=KEY123&token=TOKEN%3D456";
afterEach(() => vi.restoreAllMocks());

describe("isValidWebhook", () => {
  it("accepts a Google Chat incoming webhook", () => {
    expect(isValidWebhook(HOOK)).toBe(true);
  });
  it.each([
    ["undefined", undefined],
    ["empty", ""],
    ["not a URL", "not a url"],
    ["http", HOOK.replace("https", "http")],
    ["another host", HOOK.replace("chat.googleapis.com", "evil.example.com")],
    ["a lookalike subdomain", HOOK.replace("chat.googleapis.com", "chat.googleapis.com.evil.com")],
    ["host only in the query", "https://evil.example.com/v1/spaces/A/messages?key=k&token=t&x=chat.googleapis.com"],
    ["userinfo trick", "https://chat.googleapis.com@evil.example.com/v1/spaces/A/messages?key=k&token=t"],
    ["credentials", HOOK.replace("https://", "https://user:pw@")],
    ["a port", HOOK.replace("chat.googleapis.com", "chat.googleapis.com:8443")],
    ["wrong path", HOOK.replace("/messages", "/other")],
    ["extra path", HOOK.replace("/messages", "/messages/extra")],
    ["no key", HOOK.replace("key=KEY123&", "")],
    ["no token", HOOK.replace("&token=TOKEN%3D456", "")],
    ["a path traversal", HOOK.replace("/v1/spaces/AAAAbcd-123_x/messages", "/v1/spaces/../x/messages")],
  ])("rejects %s", (_n, value) => {
    expect(isValidWebhook(value as string | undefined)).toBe(false);
  });
});

describe("sendChat", () => {
  const ok: FetchLike = async () => new Response("{}", { status: 200 });

  it("posts the message as JSON to the webhook", async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const result = await sendChat(async (url, init) => (seen.push({ url, init }), new Response("{}")), HOOK, { text: "hi" });
    expect(result).toBe("sent");
    expect(seen[0]?.url).toBe(HOOK);
    expect(seen[0]?.init.method).toBe("POST");
    expect(JSON.parse(seen[0]?.init.body as string)).toEqual({ text: "hi" });
    expect((seen[0]?.init.headers as Record<string, string>)["content-type"]).toMatch(/application\/json/);
    expect(seen[0]?.init.signal).toBeInstanceOf(AbortSignal);
  });
  it.each([undefined, ""])("skips, without calling fetch, when no webhook is configured (%j)", async (hook) => {
    const fetchFn = vi.fn(ok);
    expect(await sendChat(fetchFn, hook, { text: "x" })).toBe("skipped");
    expect(fetchFn).not.toHaveBeenCalled();
  });
  it("refuses to post to anything that is not a Chat webhook, and does not call fetch", async () => {
    const fetchFn = vi.fn(ok);
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await sendChat(fetchFn, "https://evil.example.com/collect", { text: "x" })).toBe("failed");
    expect(fetchFn).not.toHaveBeenCalled();
  });
  it.each([400, 403, 404, 429, 500])("reports failure on HTTP %d without throwing", async (status) => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await sendChat(async () => new Response("", { status }), HOOK, { text: "x" })).toBe("failed");
  });
  it("reports failure, without throwing, when the network fails or times out", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await sendChat(async () => { throw new TypeError("network down"); }, HOOK, { text: "x" })).toBe("failed");
    expect(await sendChat(async () => { throw new DOMException("timeout", "TimeoutError"); }, HOOK, { text: "x" })).toBe("failed");
  });
  it("never logs the webhook URL, its key or its token, on any failure path", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    await sendChat(async () => new Response("", { status: 500 }), HOOK, { text: "x" });
    await sendChat(async () => { throw new Error(`failed to reach ${HOOK}`); }, HOOK, { text: "x" });
    await sendChat(ok, "https://evil.example.com/?key=KEY123&token=TOKEN", { text: "x" });
    const logged = JSON.stringify(spy.mock.calls);
    for (const secret of ["KEY123", "TOKEN", "AAAAbcd", "chat.googleapis.com"]) expect(logged).not.toContain(secret);
    expect(spy).toHaveBeenCalledTimes(3);
  });
});

describe("safeToken", () => {
  it("keeps real package names and versions intact", () => {
    for (const v of ["lodash", "@babel/core", "typing-extensions", "left-pad", "1.0.0-rc.1+build.5", "2.0.0~dev", "a_b.c"]) expect(safeToken(v)).toBe(v);
  });
  it("neutralises markup and link syntax from an attacker-chosen name", () => {
    const evil = safeToken("pkg<https://evil.example|click here>`*bold*");
    expect(evil).not.toMatch(/[<>`*| ]/);
    expect(evil).toBe("pkg?https://evil.example?click?here???bold?");
  });
  it("bounds the length", () => {
    expect(safeToken("a".repeat(500))).toBe(`${"a".repeat(100)}…`);
    expect(safeToken("a".repeat(500), 10)).toBe(`${"a".repeat(10)}…`);
  });
  it("never returns an empty string, so a code span is never empty", () => {
    expect(safeToken("")).toBe("?");
    expect(safeToken(null)).toBe("?");
    expect(safeToken(undefined)).toBe("?");
  });
});

describe("safeText", () => {
  it("replaces markup characters and control characters, and collapses whitespace", () => {
    expect(safeText("a <b> `c` *d* _e_ ~f~ \\g\nh\t i")).toBe("a b c d e f g h i");
  });
  it("bounds the length and tolerates null", () => {
    expect(safeText("x".repeat(300), 50)).toBe(`${"x".repeat(50)}…`);
    expect(safeText(null)).toBe("");
  });
});

describe("malwareMessage", () => {
  const base = { ecosystem: "npm" as const, name: "evil-pkg", version: "1.2.3", user: "dev@example.com", blocked: true, reason: "osv-malware" as const, osvIds: ["MAL-2026-1"] };
  it("says blocked when the download was stopped", () => {
    const t = malwareMessage(base).text;
    expect(t).toContain("*blocked*");
    expect(t).toContain("`evil-pkg@1.2.3`");
    expect(t).toContain("(npm)");
    expect(t).toContain("`dev@example.com`");
    expect(t).toContain("<https://osv.dev/vulnerability/MAL-2026-1|MAL-2026-1>");
    expect(t).not.toContain("not blocked");
  });
  it("is honest that it was only observed when enforcement is off", () => {
    expect(malwareMessage({ ...base, blocked: false }).text).toContain("observed, not blocked");
  });
  it("includes the reference when there is one, and omits it otherwise", () => {
    expect(malwareMessage({ ...base, reference: "PG-7Q2K4M" }).text).toContain("Reference: `PG-7Q2K4M`");
    expect(malwareMessage(base).text).not.toContain("Reference:");
    expect(malwareMessage({ ...base, reference: null }).text).not.toContain("Reference:");
  });
  it("only prints a reference that has the real shape, so nothing else can be smuggled in", () => {
    for (const bad of ["PG-7Q2K4M`*bold*", "<https://evil.example|x>", "free text", "pg-7q2k4m"]) {
      expect(malwareMessage({ ...base, reference: bad }).text, bad).not.toContain("Reference:");
    }
  });
  it("labels PyPI and an override-sourced block differently", () => {
    const t = malwareMessage({ ...base, ecosystem: "pypi", reason: "override", osvIds: [] }).text;
    expect(t).toContain("(PyPI)");
    expect(t).toContain("on the block list");
    expect(t).not.toContain("Advisories:");
  });
  it("caps the advisory list", () => {
    const t = malwareMessage({ ...base, osvIds: Array.from({ length: 9 }, (_, i) => `MAL-${i}`) }).text;
    expect(t).toContain("and 4 more");
    expect(t).not.toContain("MAL-5");
  });
  it("omits the version when there is none, and copes with a missing user", () => {
    const t = malwareMessage({ ...base, version: null, user: null }).text;
    expect(t).toContain("`evil-pkg`");
    expect(t).toContain("`unknown`");
  });
  it("cannot be made to render a link or formatting by a hostile package name, version or user", () => {
    const t = malwareMessage({ ...base, name: "x<https://evil.example|free-money>", version: "1*2*3", user: "a`b@c.d" }).text;
    expect(t).not.toContain("<https://evil.example");
    const ownLinks = t.match(/<[^>]*>/g) ?? [];
    expect(ownLinks.every((l) => l.startsWith("<https://osv.dev/"))).toBe(true);
    expect(t).not.toContain("*2*");
  });
  it("encodes an advisory id placed in a URL", () => {
    expect(malwareMessage({ ...base, osvIds: ["a/b?c"] }).text).toContain("https://osv.dev/vulnerability/a%2Fb%3Fc");
  });
});

describe("refreshMessage", () => {
  const ok = { status: "complete" as const, kind: "daily", trigger: "cron", added: 19, updated: 6, removed: 0, errors: 0, total: 25, seconds: 6.8, detail: null, dashboardUrl: "https://pkgguard.example.com" };
  it("summarises a completed run, with a link", () => {
    const t = refreshMessage(ok).text;
    expect(t).toContain("✅");
    expect(t).toContain("19 added, 6 updated (25 records in 7s)");
    expect(t).toContain("<https://pkgguard.example.com|Open the dashboard>");
    expect(t).not.toContain("withdrawn");
    expect(t).not.toContain("retried");
  });
  it("mentions withdrawn records and records to retry only when present", () => {
    const t = refreshMessage({ ...ok, removed: 2, errors: 3 }).text;
    expect(t).toContain("2 withdrawn");
    expect(t).toContain("3 records could not be fetched and will be retried");
  });
  it("reports a failure with its reason, and neutralises markup in it", () => {
    const t = refreshMessage({ ...ok, status: "failed", detail: "HTTP 503 <https://evil|x>" }).text;
    expect(t).toContain("❌");
    expect(t).toContain("failed");
    expect(t).toContain("HTTP 503");
    expect(t).not.toContain("<https://evil");
  });
  it("has no link or duration when they are unknown", () => {
    const t = refreshMessage({ ...ok, dashboardUrl: null, seconds: null }).text;
    expect(t).not.toContain("dashboard");
    expect(t).toContain("(25 records)");
  });
});

describe("overrideMessage", () => {
  const base = { action: "added" as const, mode: "block" as const, ecosystem: "npm" as const, name: "left-pad", versions: null, note: "emergency", actor: "ops@example.com" };
  it("describes a block override on all versions", () => {
    const t = overrideMessage(base).text;
    expect(t).toContain("*Block override added*");
    expect(t).toContain("`left-pad` (npm), all versions");
    expect(t).toContain("`ops@example.com`");
    expect(t).toContain("Note: emergency");
  });
  it("lists specific versions, capped", () => {
    const t = overrideMessage({ ...base, mode: "allow", action: "removed", versions: ["1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4", "1.0.5", "1.0.6"] }).text;
    expect(t).toContain("*Allow override removed*");
    expect(t).toContain("and 2 more");
    expect(t).not.toContain("1.0.5");
  });
  it("omits an absent note and neutralises a hostile one", () => {
    expect(overrideMessage({ ...base, note: null }).text).not.toContain("Note:");
    expect(overrideMessage({ ...base, note: "see <https://evil|here>" }).text).not.toContain("<https://evil");
  });
});

describe("malwareAlertKey", () => {
  const bytes = (k: string) => new TextEncoder().encode(k).length;
  it("is per ecosystem, lowercased name and lowercased user", () => {
    expect(malwareAlertKey("npm", "Left-Pad", "Dev@Example.com")).toBe("alert:malware:npm:left-pad:dev@example.com");
    expect(malwareAlertKey("pypi", "left-pad", "a@b.c")).not.toBe(malwareAlertKey("npm", "left-pad", "a@b.c"));
  });
  it("differs per user, so each affected person gets an alert", () => {
    expect(malwareAlertKey("npm", "x", "a@example.com")).not.toBe(malwareAlertKey("npm", "x", "b@example.com"));
  });
  it("treats the same person in another case as the same user", () => {
    expect(malwareAlertKey("npm", "x", "A@Example.com")).toBe(malwareAlertKey("npm", "x", "a@example.com"));
  });
  it("puts every unidentified download in one shared bucket, distinct from any real user", () => {
    const anon = malwareAlertKey("npm", "x", null);
    expect(malwareAlertKey("npm", "x", undefined)).toBe(anon);
    expect(malwareAlertKey("npm", "x", "")).toBe(anon);
    expect(malwareAlertKey("npm", "x", "   ")).toBe(anon);
    expect(anon).not.toBe(malwareAlertKey("npm", "x", "anonymous"));
    expect(anon).not.toBe(malwareAlertKey("npm", "y", null));
  });
  it("stays within KV's 512 bytes even with a maximal name and a long multi-byte user", () => {
    for (const user of ["u".repeat(400), "é".repeat(300), "日".repeat(300), "😀".repeat(300)]) {
      for (const name of ["x".repeat(900), "日".repeat(400)]) expect(bytes(malwareAlertKey("pypi", name, user)), `${name[0]}/${user[0]}`).toBeLessThanOrEqual(512);
    }
  });
  it("ignores surrounding whitespace in the user", () => {
    expect(malwareAlertKey("npm", "x", "  a@example.com\t")).toBe(malwareAlertKey("npm", "x", "a@example.com"));
  });
  it("keeps different users distinct even when the package name is as long as it can be", () => {
    const name = "x".repeat(214);
    expect(malwareAlertKey("pypi", name, "alice@example.com")).not.toBe(malwareAlertKey("pypi", name, "bob@example.com"));
  });
  it("never cuts a character in half", () => {
    const key = malwareAlertKey("npm", "x", "😀".repeat(300));
    expect(key).not.toContain("\uFFFD");
    expect(new TextDecoder("utf-8", { fatal: true }).decode(new TextEncoder().encode(key))).toBe(key);
  });
  it("keeps a realistic name and email intact", () => {
    const user = `${"a".repeat(64)}@${"b".repeat(180)}.com`;
    expect(malwareAlertKey("npm", `@scope/${"n".repeat(100)}`, user)).toContain(user);
  });
});

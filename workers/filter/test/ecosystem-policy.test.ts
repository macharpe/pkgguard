import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OsvRecord } from "@pkgguard/core";
import ctxJson from "../../../packages/core/test/fixtures/GHSA-4g82-3jcr-q52w.json";
import eventStreamJson from "../../../packages/core/test/fixtures/GHSA-mh6f-8j2x-4483.json";
import { enforces, readSettings } from "../src/env.js";
import { mostSevere, type Decision, type DetectionVerdict } from "../src/decide.js";
import { PYPI, NPM, detections, reset, run, seed, tarball } from "./harness.js";

const eventStream = eventStreamJson as unknown as OsvRecord;
const ctxRecord = ctxJson as unknown as OsvRecord;

const base = { OSV_API_TIMEOUT_MS: "400", NEGATIVE_CACHE_TTL_S: "3600", ENFORCE: "true" };

describe("readSettings: observe-only ecosystems", () => {
  it.each([
    [undefined, []],
    ["", []],
    ["   ", []],
    ["pypi", ["pypi"]],
    [" npm , pypi ", ["npm", "pypi"]],
    ["pypi,pypi", ["pypi"]],
    // Unknown ids are dropped here; the deploy generator is what refuses them.
    ["pipy", []],
    ["pypi,pipy", ["pypi"]],
    ["PyPI", []],
    ["constructor,__proto__", []],
  ])("reads %j as %j", (raw, expected) => {
    expect([...readSettings({ ...base, OBSERVE_ONLY: raw }).observeOnly].sort()).toEqual([...expected].sort());
  });
});

describe("enforces", () => {
  it.each([
    [true, [], "npm", true],
    [true, [], "pypi", true],
    [true, ["pypi"], "pypi", false],
    [true, ["pypi"], "npm", true],
    [true, ["npm", "pypi"], "npm", false],
    [false, [], "npm", false],
    [false, ["pypi"], "npm", false],
  ] as const)("enforce=%s observe-only=%j, %s blocks: %s", (enforce, observeOnly, ecosystem, expected) => {
    expect(enforces({ enforce, observeOnly: new Set(observeOnly) }, ecosystem)).toBe(expected);
  });
});

describe("mostSevere", () => {
  const reading = (verdict: DetectionVerdict, label: string) => ({
    label,
    decision: { block: verdict === "blocked", verdict, reason: null, osvIds: [], source: "index" } satisfies Decision,
  });

  it("is the only reading when there is one", () => {
    expect(mostSevere([reading("allowed", "a")]).label).toBe("a");
  });
  it("puts a block over a flag, a flag over an allow, an allow over a lookup that failed", () => {
    expect(mostSevere([reading("allowed", "a"), reading("blocked", "b"), reading("flagged", "c")]).label).toBe("b");
    expect(mostSevere([reading("allowed", "a"), reading("flagged", "b")]).label).toBe("b");
    expect(mostSevere([reading("error", "a"), reading("allowed", "b")]).label).toBe("b");
  });
  it("keeps the earliest reading on a tie", () => {
    expect(mostSevere([reading("flagged", "first"), reading("flagged", "second")]).label).toBe("first");
    expect(mostSevere([reading("error", "first"), reading("error", "second")]).label).toBe("first");
  });
});

describe("a download of an observe-only ecosystem", () => {
  beforeEach(async () => {
    await reset();
    await seed(eventStream, "npm", "event-stream");
    await seed(ctxRecord, "pypi", "ctx");
  });
  afterEach(() => vi.restoreAllMocks());

  it("is not stopped, and is recorded as flagged, while the other ecosystems still block", async () => {
    const env = { ENFORCE: "true", OBSERVE_ONLY: "pypi" };

    const pypi = await run(`${PYPI}/ctx-0.1.2.tar.gz`, { env });
    expect(pypi.response).toBe(pypi.upstream);
    expect(pypi.next).toHaveBeenCalledOnce();

    const npm = await run(tarball("event-stream", "3.3.6"), { env });
    expect(npm.response.status).toBe(403);
    expect(npm.next).not.toHaveBeenCalled();

    expect(await detections()).toEqual([
      expect.objectContaining({ ecosystem: "pypi", package_name: "ctx", verdict: "flagged", reason: "osv-malware" }),
      expect.objectContaining({ ecosystem: "npm", package_name: "event-stream", verdict: "blocked", reason: "osv-malware" }),
    ]);
  });

  it("keeps its reference, so the row can still be found by it", async () => {
    await run(`${PYPI}/ctx-0.1.2.tar.gz`, { env: { ENFORCE: "true", OBSERVE_ONLY: "pypi" } });
    expect((await detections())[0]?.reference).toMatch(/^PG-[0-9A-HJKMNP-TV-Z]{6}$/);
  });

  it("is blocked again the moment it leaves the list", async () => {
    const { response } = await run(`${PYPI}/ctx-0.1.2.tar.gz`, { env: { ENFORCE: "true", OBSERVE_ONLY: "" } });
    expect(response.status).toBe(403);
  });

  it("ignores a list that names no real ecosystem, rather than observing everything", async () => {
    const { response } = await run(`${PYPI}/ctx-0.1.2.tar.gz`, { env: { ENFORCE: "true", OBSERVE_ONLY: "pipy" } });
    expect(response.status).toBe(403);
  });

  it("never blocks anything when enforcement is off, whatever the list says", async () => {
    for (const OBSERVE_ONLY of ["", "pypi", "npm,pypi"]) {
      const { response } = await run(tarball("event-stream", "3.3.6"), { env: { ENFORCE: "false", OBSERVE_ONLY } });
      expect(response.status).toBe(200);
    }
  });
});

describe("a forwarded request the Worker does not recognise", () => {
  beforeEach(reset);
  afterEach(() => vi.restoreAllMocks());

  const warned = (spy: ReturnType<typeof vi.spyOn>): Array<Record<string, unknown>> =>
    spy.mock.calls.map((call: unknown[]) => JSON.parse(String(call[0])) as Record<string, unknown>).filter((entry: Record<string, unknown>) => String(entry["msg"]).includes("not a package download"));

  it("passes through, records nothing, and says so without naming the package or the query", async () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { response, next, upstream } = await run(`${NPM}/secret-internal-pkg/-/secret-internal-pkg-9.9.9.zip?token=SUPERSECRET`, { env: { ENFORCE: "true" } });
    expect(response).toBe(upstream);
    expect(next).toHaveBeenCalledOnce();
    expect(await detections()).toEqual([]);

    const entries = warned(spy);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({ msg: expect.any(String), host: "registry.npmjs.org", extension: ".zip", depth: 3 });
    const text = JSON.stringify(spy.mock.calls);
    expect(text).not.toContain("SUPERSECRET");
    expect(text).not.toContain("secret-internal-pkg");
    expect(text).not.toContain("9.9.9");
  });

  it.each([
    ["https://registry.npmjs.org/a/-/a-1.0.0.TGZ", ".tgz"],
    ["https://x.example/p/a-1.0.tar.gz.asc", ".asc"],
    ["https://x.example/p/my.project.v2-1.0.exe", ""],
    ["https://x.example/p/foo.bar.baz", ""],
    ["https://x.example/", ""],
  ])("names the kind of file only from a fixed list: %s", async (url, kind) => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    await run(url, { env: { ENFORCE: "true" } });
    const entries = warned(spy);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({ extension: kind });
  });

  it("does not warn for a download it does recognise", async () => {
    const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
    await run(tarball("left-pad", "1.3.0"), { env: { ENFORCE: "true" } });
    expect(warned(spy)).toEqual([]);
  });
});

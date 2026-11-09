import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OsvRecord } from "@pkgguard/core";
import hypertJson from "../../../packages/core/test/fixtures/go-MAL-2025-2544.json";
import powermuxJson from "../../../packages/core/test/fixtures/go-GO-2021-0237.json";
import { detections, reset, run, seed } from "./harness.js";

const hypert = hypertJson as unknown as OsvRecord;
const powermux = powermuxJson as unknown as OsvRecord;

const PROXY = "https://proxy.golang.org";
const zip = (path: string, version: string) => `${PROXY}/${path}/@v/${version}.zip`;
// No live OSV lookup: these tests are about the index.
const ENFORCING = { ENFORCE: "true", OSV_API_TIMEOUT_MS: "0" };

beforeEach(async () => {
  await reset();
  await seed(hypert, "go", "github.com/belatedplanet/hypert");
  await seed(powermux, "go", "github.com/AndrewBurian/powermux");
});
afterEach(() => vi.restoreAllMocks());

describe("Go downloads through the filter", () => {
  it("blocks malware at any version with a 403 and a reference, and never calls next", async () => {
    const { response, next } = await run(zip("github.com/belatedplanet/hypert", "v1.0.0"), { env: ENFORCING });
    expect(response.status).toBe(403);
    expect(next).not.toHaveBeenCalled();
    const [row] = await detections();
    expect(row).toMatchObject({
      ecosystem: "go",
      package_name: "github.com/belatedplanet/hypert",
      version: "v1.0.0",
      purl: "pkg:golang/github.com/belatedplanet/hypert@v1.0.0",
      verdict: "blocked",
      reason: "osv-malware",
    });
    expect(row?.reference).toMatch(/^PG-[A-Z0-9]{6}$/);
    expect(await response.text()).toContain(row?.reference as string);
  });

  it("blocks a pseudo-version, which is how an untagged commit is fetched", async () => {
    const { response } = await run(zip("github.com/belatedplanet/hypert", "v0.0.0-20250101000000-0123456789ab"), { env: ENFORCING });
    expect(response.status).toBe(403);
  });

  it("only observes it while Go is in OBSERVE_ONLY: flagged, passed on, and recorded as flagged", async () => {
    const { response, next, upstream } = await run(zip("github.com/belatedplanet/hypert", "v1.0.0"), { env: { ...ENFORCING, OBSERVE_ONLY: "go" } });
    expect(next).toHaveBeenCalledOnce();
    expect(response).toBe(upstream);
    expect((await detections())[0]).toMatchObject({ verdict: "flagged", reason: "osv-malware" });
  });

  it("records a module with capitals under its exact name, decoded from the proxy's `!` escape", async () => {
    const { response, next } = await run(zip("github.com/!andrew!burian/powermux", "v1.1.0"), { env: ENFORCING });
    // A vulnerability is logged, never blocked.
    expect(response.status).toBe(200);
    expect(next).toHaveBeenCalledOnce();
    expect((await detections())[0]).toMatchObject({
      ecosystem: "go",
      package_name: "github.com/AndrewBurian/powermux",
      purl: "pkg:golang/github.com/AndrewBurian/powermux@v1.1.0",
      verdict: "flagged",
      reason: "osv-cve",
    });
  });

  it("does not apply one module's advisory to the module that differs from it only by case", async () => {
    const { next } = await run(zip("github.com/andrewburian/powermux", "v1.1.0"), { env: ENFORCING });
    expect(next).toHaveBeenCalledOnce();
    expect((await detections())[0]).toMatchObject({ package_name: "github.com/andrewburian/powermux", verdict: "allowed" });
  });

  it("passes the metadata requests through and records nothing", async () => {
    for (const file of ["v1.0.0.info", "v1.0.0.mod", "list"]) {
      const { next } = await run(`${PROXY}/github.com/belatedplanet/hypert/@v/${file}`, { env: ENFORCING });
      expect(next, file).toHaveBeenCalledOnce();
    }
    const { next } = await run(`${PROXY}/github.com/belatedplanet/hypert/@latest`, { env: ENFORCING });
    expect(next).toHaveBeenCalledOnce();
    expect(await detections()).toEqual([]);
  });
});

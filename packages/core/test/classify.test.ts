import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { classify, collectCweIds, MALWARE_CWES } from "../src/osv/classify.js";
import type { OsvRecord } from "../src/osv/types.js";

function fixture(id: string): OsvRecord {
  return JSON.parse(readFileSync(new URL(`./fixtures/${id}.json`, import.meta.url), "utf8")) as OsvRecord;
}

describe("classify — real OSV fixtures", () => {
  const malware: Array<[string, string]> = [
    ["event-stream", "GHSA-mh6f-8j2x-4483"],
    ["coa", "GHSA-73qr-pfmq-6rp8"],
    ["ctx (PyPI, CWE-912)", "GHSA-4g82-3jcr-q52w"],
    ["@solana/web3.js", "MAL-2024-11183"],
    ["node-ipc", "MAL-2026-3744"],
  ];
  it.each(malware)("%s is malware", (_name, id) => {
    expect(classify(fixture(id))).toBe("malware");
  });

  it("event-stream has no MAL- id, so the CWE rule is what catches it", () => {
    const record = fixture("GHSA-mh6f-8j2x-4483");
    expect(record.id.startsWith("MAL-")).toBe(false);
    expect((record.aliases ?? []).some((a) => a.startsWith("MAL-"))).toBe(false);
    expect(collectCweIds(record)).toContain("CWE-506");
  });

  it("ua-parser-js ReDoS (CWE-400) is a vulnerability — negative control", () => {
    expect(classify(fixture("GHSA-394c-5j6w-4xmx"))).toBe("vulnerability");
  });

  it("lodash command injection (CWE-77/94) is a vulnerability", () => {
    expect(classify(fixture("GHSA-35jh-r3h4-6jhm"))).toBe("vulnerability");
  });
});

describe("classify — each rule in isolation", () => {
  const base: OsvRecord = { id: "GHSA-xxxx-xxxx-xxxx", modified: "2026-01-01T00:00:00Z" };

  it("MAL- id alone", () => {
    expect(classify({ ...base, id: "MAL-2026-1" })).toBe("malware");
  });
  it("MAL- alias alone", () => {
    expect(classify({ ...base, aliases: ["CVE-2026-1", "MAL-2026-2"] })).toBe("malware");
  });
  it("top-level cwe_ids alone", () => {
    expect(classify({ ...base, database_specific: { cwe_ids: ["CWE-506"] } })).toBe("malware");
  });
  it("affected[].database_specific.cwes alone", () => {
    expect(
      classify({ ...base, affected: [{ database_specific: { cwes: [{ cweId: "CWE-912" }] } }] }),
    ).toBe("malware");
  });
  it.each([...MALWARE_CWES])("%s is a malware CWE", (cwe) => {
    expect(classify({ ...base, database_specific: { cwe_ids: [cwe] } })).toBe("malware");
  });
  it("ordinary CWEs and no signals are a vulnerability", () => {
    expect(classify({ ...base, database_specific: { cwe_ids: ["CWE-79", "CWE-400"] } })).toBe("vulnerability");
    expect(classify(base)).toBe("vulnerability");
  });
  it("does not match a MAL- substring elsewhere in the id", () => {
    expect(classify({ ...base, id: "GHSA-MAL-1234" })).toBe("vulnerability");
  });
  it("does not classify on summary text", () => {
    expect(classify({ ...base, summary: "Malicious code in leftpad (npm)" })).toBe("vulnerability");
  });
  it("tolerates malformed CWE entries", () => {
    const record = {
      ...base,
      database_specific: { cwe_ids: [null, 5, "CWE-79"] },
      affected: [{ database_specific: { cwes: [{}, null, { cweId: 7 }] } }],
    } as unknown as OsvRecord;
    expect(classify(record)).toBe("vulnerability");
  });
});

describe("collectCweIds", () => {
  it("dedupes across both locations", () => {
    const ids = collectCweIds(fixture("MAL-2026-3744"));
    expect(ids).toEqual(["CWE-506"]);
  });
  it("returns empty when none", () => {
    expect(collectCweIds({ id: "X", modified: "" })).toEqual([]);
  });
});

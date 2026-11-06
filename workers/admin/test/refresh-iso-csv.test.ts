import { describe, expect, it } from "vitest";
import { isAtOrAfter, maxIso, normalizeIso } from "../src/refresh/iso.js";
import { DeltaTooLarge, scanModifiedCsv } from "../src/refresh/modified-csv.js";

const stream = (text: string, chunk = text.length || 1): ReadableStream<Uint8Array> => {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) return controller.close();
      controller.enqueue(bytes.slice(offset, offset + chunk));
      offset += chunk;
    },
  });
};

describe("normalizeIso", () => {
  it("pads the fraction to nine digits", () => {
    expect(normalizeIso("2026-11-06T11:30:04Z")).toBe("2026-11-06T11:30:04.000000000Z");
    expect(normalizeIso("2026-11-06T11:30:04.5Z")).toBe("2026-11-06T11:30:04.500000000Z");
    expect(normalizeIso("2026-11-06T11:30:04.463693441Z")).toBe("2026-11-06T11:30:04.463693441Z");
  });
  it.each(["", "garbage", "2026-11-06", "2026-11-06T11:30:04+01:00", "2026-13-40T11:30:04Z", "2026-11-06T11:30:04.1234567890Z"])("rejects %j", (v) => {
    expect(normalizeIso(v)).toBeNull();
  });
});

describe("isAtOrAfter", () => {
  it("orders mixed precision correctly, which plain string comparison does not", () => {
    // '.' sorts before 'Z', so a naive compare says 04.4Z < 04Z, which is wrong.
    expect("2026-11-06T11:30:04.4Z" < "2026-11-06T11:30:04Z").toBe(true);
    expect(isAtOrAfter("2026-11-06T11:30:04.4Z", "2026-11-06T11:30:04Z")).toBe(true);
    expect(isAtOrAfter("2026-11-06T11:30:03.999999999Z", "2026-11-06T11:30:04Z")).toBe(false);
  });
  it("includes the boundary, so the last-seen record is re-fetched harmlessly", () => {
    expect(isAtOrAfter("2026-11-06T11:30:04.463693441Z", "2026-11-06T11:30:04.463693441Z")).toBe(true);
  });
  it("treats an unparseable value as newer, so it is fetched and not silently skipped", () => {
    expect(isAtOrAfter("garbage", "2026-11-06T11:30:04Z")).toBe(true);
    expect(isAtOrAfter("2026-11-06T11:30:04Z", "garbage")).toBe(true);
  });
});

describe("maxIso", () => {
  it("picks the chronologically newest, ignoring unparseable values", () => {
    expect(maxIso(["2026-11-06T11:30:04Z", "2026-11-06T11:30:04.4Z", "junk", "2026-11-05T00:00:00Z"])).toBe("2026-11-06T11:30:04.4Z");
    expect(maxIso([])).toBeNull();
    expect(maxIso(["junk"])).toBeNull();
  });
});

describe("scanModifiedCsv", () => {
  const csv = ["2026-11-06T12:00:00Z,GHSA-new1", "2026-11-06T11:30:04.5Z,GHSA-new2", "2026-11-06T11:30:04Z,GHSA-edge", "2026-11-01T00:00:00Z,GHSA-old"].join("\n") + "\n";

  it("keeps entries at or after since, counts every record, and preserves order", async () => {
    const r = await scanModifiedCsv(stream(csv), "2026-11-06T11:30:04Z", 100);
    expect(r.items.map((i) => i.id)).toEqual(["GHSA-new1", "GHSA-new2", "GHSA-edge"]);
    expect(r.total).toBe(4);
    expect(r.malformed).toBe(0);
  });
  it("returns everything when since is null", async () => {
    expect((await scanModifiedCsv(stream(csv), null, 100)).items).toHaveLength(4);
  });
  it("is correct whatever the chunk boundaries, including one byte at a time", async () => {
    for (const size of [1, 3, 7, 50]) {
      const r = await scanModifiedCsv(stream(csv, size), "2026-11-06T11:30:04Z", 100);
      expect(r.items.map((i) => i.id), `chunk ${size}`).toEqual(["GHSA-new1", "GHSA-new2", "GHSA-edge"]);
      expect(r.total, `chunk ${size}`).toBe(4);
    }
  });
  it("handles CRLF, blank lines and a missing final newline", async () => {
    const r = await scanModifiedCsv(stream("2026-11-06T12:00:00Z,A-1\r\n\r\n2026-11-06T13:00:00Z,B-2"), null, 10);
    expect(r.items.map((i) => i.id)).toEqual(["A-1", "B-2"]);
    expect(r.total).toBe(2);
  });
  it("counts malformed lines separately and never fetches them", async () => {
    const hostile = ["no-comma-here", ",GHSA-x", "2026-11-06T12:00:00Z,", "2026-11-06T12:00:00Z,../../etc/passwd", "2026-11-06T12:00:00Z,a/b", "2026-11-06T12:00:00Z,a b", "2026-11-06T12:00:00Z,GHSA-ok"].join("\n");
    const r = await scanModifiedCsv(stream(hostile), null, 10);
    expect(r.items.map((i) => i.id)).toEqual(["GHSA-ok"]);
    expect(r.malformed).toBe(6);
    expect(r.total).toBe(1);
  });
  it("accepts every real OSV id shape", async () => {
    const ids = ["GHSA-mh6f-8j2x-4483", "MAL-2026-4179", "PYSEC-2023-74", "CVE-2021-23337", "OSV-2024-1"];
    const r = await scanModifiedCsv(stream(ids.map((id) => `2026-11-06T12:00:00Z,${id}`).join("\n")), null, 10);
    expect(r.items.map((i) => i.id)).toEqual(ids);
  });
  it("refuses a delta over the limit instead of grinding through it", async () => {
    const big = Array.from({ length: 6 }, (_, i) => `2026-11-06T12:00:0${i}Z,GHSA-${i}`).join("\n");
    await expect(scanModifiedCsv(stream(big), null, 5)).rejects.toBeInstanceOf(DeltaTooLarge);
    await expect(scanModifiedCsv(stream(big), null, 6)).resolves.toMatchObject({ total: 6 });
  });
  it("does not count entries older than since toward the limit", async () => {
    const lines = Array.from({ length: 50 }, (_, i) => `2020-01-01T00:00:${String(i).padStart(2, "0")}Z,OLD-${i}`).join("\n");
    await expect(scanModifiedCsv(stream(lines), "2026-01-01T00:00:00Z", 5)).resolves.toMatchObject({ items: [], total: 50 });
  });
  it("handles an empty file", async () => {
    expect(await scanModifiedCsv(stream(""), null, 5)).toEqual({ items: [], total: 0, malformed: 0 });
  });
  it("decodes multi-byte characters split across chunks without corrupting ids", async () => {
    const r = await scanModifiedCsv(stream("2026-11-06T12:00:00Z,GHSA-ok\n2026-11-06T12:00:01Z,GHSA-é\n", 1), null, 10);
    expect(r.items.map((i) => i.id)).toEqual(["GHSA-ok"]);
    expect(r.malformed).toBe(1);
  });
});

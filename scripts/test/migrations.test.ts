import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { listMigrations, orderMigrations } from "../lib/migrations.js";

describe("listMigrations", () => {
  let dir: string;
  const add = (...names: string[]) => names.forEach((n) => writeFileSync(join(dir, n), "-- sql\n"));
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pkgguard-mig-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("returns every migration, in numeric order whatever order the files were created in", () => {
    add("0003_c.sql", "0001_a.sql", "0002_b.sql");
    expect(listMigrations(dir)).toEqual(["0001_a.sql", "0002_b.sql", "0003_c.sql"]);
  });
  it("ignores files that are not SQL", () => {
    add("0001_a.sql", "README.md", "notes.txt");
    expect(listMigrations(dir)).toEqual(["0001_a.sql"]);
  });
  it("refuses an empty directory", () => {
    expect(() => listMigrations(dir)).toThrow(/no \.sql migrations/);
  });
  it("sorts by number whatever order the filesystem lists them in, which only a shuffled list can prove", () => {
    expect(orderMigrations(["0003_c.sql", "0001_a.sql", "0002_b.sql"])).toEqual(["0001_a.sql", "0002_b.sql", "0003_c.sql"]);
    expect(orderMigrations(["0002_b.sql", "0003_c.sql", "0001_a.sql"])).toEqual(["0001_a.sql", "0002_b.sql", "0003_c.sql"]);
    expect(orderMigrations(["0010_j.sql", "0009_i.sql", "0001_a.sql", "0002_b.sql", "0003_c.sql", "0004_d.sql", "0005_e.sql", "0006_f.sql", "0007_g.sql", "0008_h.sql"])).toHaveLength(10);
  });
  it("refuses a gap, because a missing migration means a schema the Workers do not expect", () => {
    add("0001_a.sql", "0003_c.sql");
    expect(() => listMigrations(dir)).toThrow(/without gaps: expected 0002, found 0003_c\.sql/);
  });
  it("refuses a sequence that does not start at 0001", () => {
    add("0002_b.sql");
    expect(() => listMigrations(dir)).toThrow(/expected 0001/);
  });
  it("refuses a duplicate number", () => {
    add("0001_a.sql", "0001_b.sql");
    expect(() => listMigrations(dir)).toThrow(/expected 0002, found 0001_b\.sql/);
  });
  it.each(["init.sql", "1_a.sql", "00001_a.sql", "0001-a.sql", "0001_A.sql", "0001_.sql"])("refuses the badly named file %s", (name) => {
    add(name);
    expect(() => listMigrations(dir)).toThrow(/does not match NNNN_name\.sql/);
  });

  it("accepts the real migrations directory, and includes the latest one, so a load can never miss it", () => {
    const real = listMigrations(resolve(import.meta.dirname, "../../migrations"));
    expect(real[0]).toBe("0001_init.sql");
    expect(real).toContain("0002_refresh_items.sql");
    expect(real).toContain("0003_detection_reference.sql");
    expect(real).toContain("0004_advisory_cvss.sql");
    expect(real.length).toBeGreaterThanOrEqual(4);
  });
});

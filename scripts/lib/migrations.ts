import { readdirSync } from "node:fs";

const NAME = /^(\d{4})_[a-z0-9_]+\.sql$/;

/**
 * The migrations to apply to a fresh database, in order. Numbered files only, and the numbers must run 0001, 0002, ...
 * with no gap: a missing migration means a schema the Workers do not expect, and that must stop a load rather than
 * surface later as a silently swallowed background write.
 *
 * Takes the names, not a directory, because `readdir` order is the filesystem's: alphabetical on macOS, arbitrary on
 * Linux, so only a test that supplies a shuffled list can prove the sort.
 */
export function orderMigrations(names: readonly string[]): string[] {
  const files = names.filter((f) => f.endsWith(".sql")).sort();
  if (files.length === 0) throw new Error("no .sql migrations found");
  files.forEach((file, index) => {
    const match = NAME.exec(file);
    if (!match) throw new Error(`migration ${JSON.stringify(file)} does not match NNNN_name.sql`);
    const expected = String(index + 1).padStart(4, "0");
    if (match[1] !== expected) throw new Error(`migrations must be numbered without gaps: expected ${expected}, found ${file}`);
  });
  return files;
}

export const listMigrations = (dir: string): string[] => orderMigrations(readdirSync(dir));

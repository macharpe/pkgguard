/**
 * Writes every distinct version string in the RubyGems OSV feed (range boundaries and listed versions), one per line, to
 * stdout. It is the input of `gem-version.rb`, which asks Ruby's own `Gem::Version` how they order.
 *
 *   npm run bootstrap -- download --ecosystem rubygems
 *   npx tsx scripts/oracles/gem-versions-input.ts > /tmp/gem-versions.txt
 */
import { join, resolve } from "node:path";
import type { OsvRecord } from "../../packages/core/src/index.js";
import { forEachJsonEntry } from "../lib/zip.js";

const versions = new Set<string>();
await forEachJsonEntry(resolve(join("scripts/data", "RubyGems.zip")), (_name, json) => {
  const record = JSON.parse(json) as OsvRecord;
  for (const affected of record.affected ?? []) {
    if (affected.package?.ecosystem !== "RubyGems") continue;
    for (const v of affected.versions ?? []) if (typeof v === "string") versions.add(v);
    for (const range of affected.ranges ?? []) {
      if (range.type === "GIT") continue;
      for (const e of range.events) for (const v of [e.introduced, e.fixed, e.last_affected]) if (typeof v === "string" && v !== "" && v !== "0") versions.add(v);
    }
  }
});
process.stdout.write([...versions].filter((v) => !/[\r\n|]/.test(v)).sort().join("\n") + "\n");

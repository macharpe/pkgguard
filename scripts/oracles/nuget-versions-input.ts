/**
 * Writes, from the NuGet OSV feed, every distinct version string (range boundaries and listed versions) to the first path,
 * and every distinct package name to the second, one per line. They are the inputs of `nuget-version/`, which asks NuGet's own
 * `NuGet.Versioning` how the versions order and how the names fold.
 *
 *   npx tsx scripts/oracles/nuget-versions-input.ts /tmp/nuget-versions.txt /tmp/nuget-names.txt
 */
import { writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { OsvRecord } from "../../packages/core/src/index.js";
import { forEachJsonEntry } from "../lib/zip.js";

const [versionsPath, namesPath] = process.argv.slice(2);
if (versionsPath === undefined || namesPath === undefined) throw new Error("usage: nuget-versions-input.ts <versions-out> <names-out>");

const versions = new Set<string>();
const names = new Set<string>();
await forEachJsonEntry(resolve(join("scripts/data", "NuGet.zip")), (_name, json) => {
  const record = JSON.parse(json) as OsvRecord;
  for (const affected of record.affected ?? []) {
    if (affected.package?.ecosystem !== "NuGet") continue;
    if (affected.package.name) names.add(affected.package.name);
    for (const v of affected.versions ?? []) if (typeof v === "string") versions.add(v);
    for (const range of affected.ranges ?? []) {
      if (range.type === "GIT") continue;
      for (const e of range.events) for (const v of [e.introduced, e.fixed, e.last_affected]) if (typeof v === "string" && v !== "" && v !== "0") versions.add(v);
    }
  }
});
const clean = (set: Set<string>) => [...set].filter((v) => !/[\r\n]/.test(v)).sort().join("\n") + "\n";
writeFileSync(versionsPath, clean(versions));
writeFileSync(namesPath, clean(names));
console.error(`${versions.size} version strings, ${names.size} names`);

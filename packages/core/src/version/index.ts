import type { Ecosystem } from "../ecosystem-ids.js";
import { ECOSYSTEMS } from "../ecosystems/index.js";

export { comparePep440, parsePep440 } from "./pep440.js";
export { compareSemver } from "./semver.js";
export { compareGem, parseGemVersion } from "./gem.js";
export { compareNuget, parseNugetVersion } from "./nuget.js";

/**
 * Ecosystem-aware comparison. Returns null when either version cannot be parsed,
 * which callers must treat as "no match" — never as equal or as affected.
 */
export function compareVersions(ecosystem: Ecosystem, a: string, b: string): -1 | 0 | 1 | null {
  return ECOSYSTEMS[ecosystem].compare(a, b);
}

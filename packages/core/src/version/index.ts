import type { Ecosystem } from "../normalize.js";
import { comparePep440 } from "./pep440.js";
import { compareSemver } from "./semver.js";

export { comparePep440, parsePep440 } from "./pep440.js";
export { compareSemver } from "./semver.js";

/**
 * Ecosystem-aware comparison. Returns null when either version cannot be parsed,
 * which callers must treat as "no match" — never as equal or as affected.
 */
export function compareVersions(ecosystem: Ecosystem, a: string, b: string): -1 | 0 | 1 | null {
  return ecosystem === "pypi" ? comparePep440(a, b) : compareSemver(a, b);
}

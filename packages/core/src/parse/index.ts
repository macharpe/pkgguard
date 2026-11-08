import { ENABLED_ECOSYSTEMS } from "../ecosystem-ids.js";
import { ECOSYSTEMS } from "../ecosystems/index.js";
import { parseNpmUrl } from "./npm.js";
import { parsePypiUrl } from "./pypi.js";
import type { ParsedPackage } from "./types.js";

export type { ParsedPackage } from "./types.js";
export { parseNpmUrl, parsePypiUrl };

/**
 * The packages a registry download URL could be, or none when it is not a recognised download. Never throws.
 * Ecosystems are tried in order and the first to recognise the URL answers, so each one's shape must be one no
 * other accepts (`ecosystems.test.ts` holds a corpus to that). Most URLs have one reading; a few file names
 * cannot be split into a name and a version without guessing, and then every plausible reading is returned.
 */
export function parsePackageCandidates(input: string | URL): ParsedPackage[] {
  let url: URL;
  try {
    url = typeof input === "string" ? new URL(input) : input;
  } catch {
    return [];
  }
  for (const id of ENABLED_ECOSYSTEMS) {
    try {
      const found = ECOSYSTEMS[id].parse(url);
      if (found.length > 0) return found;
    } catch {
      // A parser that throws is a parser that did not recognise the URL: this must stay total.
    }
  }
  return [];
}

/** The first reading of a registry download URL, or null. Total: never throws. */
export function parsePackageUrl(input: string | URL): ParsedPackage | null {
  return parsePackageCandidates(input)[0] ?? null;
}

/** Package URL per the purl spec. npm scope is percent-encoded as `%40scope`. */
export function toPurl(pkg: ParsedPackage): string {
  const spec = ECOSYSTEMS[pkg.ecosystem];
  const ns = pkg.namespace ? `${encodeURIComponent(pkg.namespace.toLowerCase())}/` : "";
  return `pkg:${spec.purlType}/${ns}${encodeURIComponent(spec.purlName(pkg.name))}@${encodeURIComponent(pkg.version)}`;
}

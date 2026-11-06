import { parseNpmUrl } from "./npm.js";
import { parsePypiUrl } from "./pypi.js";
import type { ParsedPackage } from "./types.js";

export type { ParsedPackage } from "./types.js";
export { parseNpmUrl, parsePypiUrl };

/** Parses a registry download URL. Total: never throws, null when not a recognised download. */
export function parsePackageUrl(input: string | URL): ParsedPackage | null {
  let url: URL;
  try {
    url = typeof input === "string" ? new URL(input) : input;
  } catch {
    return null;
  }
  return parseNpmUrl(url) ?? parsePypiUrl(url);
}

/** Package URL per the purl spec. npm scope is percent-encoded as `%40scope`. */
export function toPurl(pkg: ParsedPackage): string {
  const name = encodeURIComponent(pkg.name.toLowerCase());
  const type = pkg.ecosystem;
  const normalizedName = type === "pypi" ? name.replace(/[-_.]+/g, "-") : name;
  const ns = pkg.namespace ? `${encodeURIComponent(pkg.namespace.toLowerCase())}/` : "";
  return `pkg:${type}/${ns}${normalizedName}@${encodeURIComponent(pkg.version)}`;
}

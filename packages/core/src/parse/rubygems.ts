import type { ParsedPackage } from "./types.js";

/** A version as a gem's file name writes it: digits, then dot-separated alphanumerics, and no hyphen. */
const VERSION_TOKEN = /^\d+(?:\.[0-9A-Za-z]+)*$/;
/** gem names: ASCII letters, digits, `.`, `_` and `-`. */
const GEM_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
/** More readings than this and the rightmost are kept: a platform-less file, the commonest, is always among them. */
const MAX_CANDIDATES = 8;

function decode(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * RubyGems downloads: `/gems/{name}-{version}.gem`, or `/gems/{name}-{version}-{platform}.gem`.
 *
 * Hyphens separate all three parts, and a name or a platform can contain digits as well. Real data shows both
 * directions are real: three malware gems have names ending in a version-looking token (`gemxy-1778522681`), and
 * platforms end in numbers (`x86_64-darwin-19`). Neither "the first version-looking token" nor "the last" is right,
 * so every plausible split is returned and the index decides: only the right name is a package that exists.
 *
 * A reading that is not a real gem costs a lookup and answers "allowed", so it cannot outvote the one that is.
 * The platform is dropped: an advisory applies to every build of a version.
 *
 * Anchored on a `gems` segment, so a mirror's path prefix is tolerated. Total: never throws.
 */
export function parseRubygemsUrl(url: URL): ParsedPackage[] {
  const segments = url.pathname.split("/").map(decode);
  if (segments.some((s) => s === null)) return [];
  const parts = segments as string[];
  const file = parts.at(-1) ?? "";
  if (parts.length < 2 || parts.at(-2) !== "gems" || !file.endsWith(".gem")) return [];

  const tokens = file.slice(0, -".gem".length).split("-");
  const found: ParsedPackage[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const version = tokens[i] as string;
    if (!VERSION_TOKEN.test(version)) continue;
    const name = tokens.slice(0, i).join("-");
    if (!GEM_NAME.test(name)) continue;
    found.push({ ecosystem: "rubygems", namespace: null, name, version });
  }
  return found.length > MAX_CANDIDATES ? found.slice(-MAX_CANDIDATES) : found;
}

import { parseGoVersion } from "../version/go.js";
import type { ParsedPackage } from "./types.js";

/** One element of a module path: letters, digits and `-._~`, not starting or ending with a dot. */
const PATH_ELEMENT = /^[A-Za-z0-9_~-](?:[A-Za-z0-9._~-]*[A-Za-z0-9_~-])?$/;
const MAX_PATH_LENGTH = 255;
/** A proxy serves canonical versions: `v`, three numeric parts, then an optional prerelease and build. Never the shorthand. */
const CANONICAL_VERSION = /^v\d+\.\d+\.\d+/;

/**
 * The Go proxy writes an uppercase letter as `!` and the lowercase letter, so that the file systems that ignore case keep
 * two modules apart: `github.com/BurntSushi/toml` is `github.com/!burnt!sushi/toml`. The decoder must be exact. A `!` that
 * is not followed by a lowercase letter, and an uppercase letter that was not escaped, are not valid encodings.
 */
export function unescapeGoPath(escaped: string): string | null {
  let out = "";
  for (let i = 0; i < escaped.length; i++) {
    const c = escaped[i] as string;
    if (c === "!") {
      const next = escaped[i + 1];
      if (next === undefined || next < "a" || next > "z") return null;
      out += next.toUpperCase();
      i++;
    } else if (c >= "A" && c <= "Z") {
      return null;
    } else {
      out += c;
    }
  }
  return out;
}

function decode(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * Go module downloads from a module proxy: `/{module}/@v/{version}.zip`.
 *
 * The module path is everything before `/@v/` and the version is the file name without `.zip`, so there is nothing to guess.
 * Only the `.zip` is a download: `.info` and `.mod` are metadata, and `@latest` and `@v/list` are listings. The path and the
 * version are both escaped as above. The module path starts at the first segment with a dot in it (the domain), which skips
 * the prefix of a mirror (`/artifactory/api/go/go-remote/github.com/…`); a path whose first element has no dot is not a
 * downloadable module. Total: never throws.
 */
export function parseGoUrl(url: URL): ParsedPackage[] {
  const segments = url.pathname.split("/").map(decode);
  // An escaped slash inside a segment is not a path separator in any proxy request, so it is not a module path.
  if (segments.some((s) => s === null || s.includes("/"))) return [];
  const parts = segments as string[];
  const file = parts.at(-1) ?? "";
  if (parts.at(-2) !== "@v" || !file.endsWith(".zip")) return [];

  // No dotted segment, or nothing between it and `@v`, leaves an empty module path, which the element check below refuses.
  const start = parts.findIndex((segment) => segment.includes("."));
  const moduleSegments = parts.slice(start, -2);

  const name = unescapeGoPath(moduleSegments.join("/"));
  const version = unescapeGoPath(file.slice(0, -".zip".length));
  if (name === null || version === null || name.length > MAX_PATH_LENGTH) return [];
  if (!name.split("/").every((element) => PATH_ELEMENT.test(element))) return [];
  if (!CANONICAL_VERSION.test(version) || parseGoVersion(version) === null) return [];
  return [{ ecosystem: "go", namespace: null, name, version }];
}

import type { ParsedPackage } from "./types.js";

/** crates.io names: ASCII letters, digits, `-` and `_`, at most 64 long. */
const CRATE_NAME = /^[A-Za-z0-9_-]{1,64}$/;
/** Crate versions are strict SemVer, so anything else in a version position is not a download. */
const CRATE_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function decode(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * Cargo downloads, in the two shapes the registry serves:
 *
 *   /crates/{name}/{version}/download        what the cargo client requests: the index's `dl` has no markers,
 *                                            so cargo appends this to it (measured behind Gateway)
 *   /crates/{name}/{name}-{version}.crate    what that redirects to, and the shape Cloudflare documents
 *
 * Both are anchored on a `crates` segment, so a mirror path prefix is tolerated (`/api/v1/crates/{name}/…`,
 * `/api/cargo/{repo}/crates/{name}/…`). Total: never throws, returns an empty list for anything else.
 */
export function parseCargoUrl(url: URL): ParsedPackage[] {
  const segments = url.pathname.split("/").map(decode);
  if (segments.some((s) => s === null)) return [];
  const parts = segments as string[];
  const last = parts.at(-1) ?? "";

  let name: string | undefined;
  let version: string | undefined;

  if (last === "download") {
    // …/crates/{name}/{version}/download
    if (parts.length < 4 || parts.at(-4) !== "crates") return [];
    name = parts.at(-3);
    version = parts.at(-2);
  } else if (last.endsWith(".crate")) {
    // …/crates/{name}/{name}-{version}.crate
    if (parts.length < 3 || parts.at(-3) !== "crates") return [];
    name = parts.at(-2);
    const prefix = `${name}-`;
    if (name === undefined || !last.startsWith(prefix)) return [];
    version = last.slice(prefix.length, -".crate".length);
  } else {
    return [];
  }

  if (name === undefined || version === undefined) return [];
  if (!CRATE_NAME.test(name) || !CRATE_VERSION.test(version)) return [];
  return [{ ecosystem: "cargo", namespace: null, name, version }];
}

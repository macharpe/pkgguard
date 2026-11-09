import type { ParsedPackage } from "./types.js";

const SDIST_EXT = /\.(tar\.gz|zip|tar\.bz2|tar\.xz)$/;

/**
 * PyPI downloads under `/packages/.../{filename}`.
 * Wheel: `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`
 * Sdist: `{name}-{version}.tar.gz` (or .zip and friends)
 * Total: never throws, returns null for anything else.
 */
export function parsePypiUrl(url: URL): ParsedPackage | null {
  if (!url.pathname.includes("/packages/")) return null;
  // A Go module proxy path (`…/packages/…/@v/{version}.zip`) has the same extension and a `/packages/` segment, and is not a
  // PyPI file: PyPI paths never contain an `@v` segment.
  if (url.pathname.includes("/@v/")) return null;
  const file = url.pathname.slice(url.pathname.lastIndexOf("/") + 1);
  let decoded: string;
  try {
    decoded = decodeURIComponent(file);
  } catch {
    return null;
  }

  if (decoded.endsWith(".whl")) {
    const parts = decoded.slice(0, -".whl".length).split("-");
    if (parts.length !== 5 && parts.length !== 6) return null;
    const [name, version] = parts;
    if (!name || !version) return null;
    return { ecosystem: "pypi", namespace: null, name, version };
  }

  const ext = SDIST_EXT.exec(decoded);
  if (ext) {
    const stem = decoded.slice(0, ext.index);
    const split = stem.lastIndexOf("-");
    if (split < 1) return null;
    const name = stem.slice(0, split);
    const version = stem.slice(split + 1);
    if (!version || !/^\d|^v\d/i.test(version)) return null;
    return { ecosystem: "pypi", namespace: null, name, version };
  }

  return null;
}

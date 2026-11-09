import { parseNugetVersion } from "../version/nuget.js";
import type { ParsedPackage } from "./types.js";

/** A NuGet id: letters, digits, `_`, and `.` or `-` between them. Unicode is legal, and the feed has ids that use it. */
const NUGET_ID = /^[\p{L}\p{N}\p{M}_]+(?:[.-][\p{L}\p{N}\p{M}_]+)*$/u;
/** The version as the flat container writes it: normalised, so no build metadata. Validated properly by the comparator. */
const NUGET_VERSION = /^\d[0-9A-Za-z.-]*$/;
const MAX_ID_LENGTH = 100;
/** More readings than this and the leftmost are kept: they have the fewest numeric tokens in the id, as real ids do. */
const MAX_CANDIDATES = 8;

function decode(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * NuGet downloads, in the two shapes Gateway forwards (both measured):
 *
 *   /v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg    what current clients request
 *   /packages/{id}.{version}.nupkg                           where the legacy v2 endpoint
 *                                                            (`/api/v2/package/{id}/{version}`) redirects, on
 *                                                            `globalcdn.nuget.org`
 *
 * Total: never throws.
 */
export function parseNugetUrl(url: URL): ParsedPackage[] {
  const segments = url.pathname.split("/").map(decode);
  if (segments.some((s) => s === null)) return [];
  const parts = segments as string[];
  return parseFlatContainer(parts) ?? parseCdn(parts);
}

/**
 * The flat container: id and version are separate path segments and the file repeats both, so there is nothing to guess:
 * the last three segments are read and the file name must be exactly `{id}.{version}.nupkg`. That is a shape no other
 * ecosystem's download has, so a mirror's path prefix is tolerated without anchoring on a segment name. The flat container
 * lowercases both, and a client sends them that way, so the file name is compared case-insensitively.
 */
function parseFlatContainer(parts: string[]): ParsedPackage[] | null {
  if (parts.length < 4) return null;
  const id = parts.at(-3) as string;
  const version = parts.at(-2) as string;
  const file = parts.at(-1) as string;
  if (id.length === 0 || id.length > MAX_ID_LENGTH || !NUGET_ID.test(id) || !NUGET_VERSION.test(version)) return null;
  if (file.toLowerCase() !== `${id}.${version}.nupkg`.toLowerCase()) return null;
  return [{ ecosystem: "nuget", namespace: null, name: id, version }];
}

/**
 * The CDN's `/packages/{id}.{version}.nupkg`: one file name holding both, joined by a dot, and a dot is also what separates an
 * id's own parts and a version's. `newtonsoft.json.13.0.3` is id `newtonsoft.json` and version `13.0.3`, but `newtonsoft.json.13`
 * and `0.3` read the same way. A real version is a run of numbers to the end of the name (or one with a prerelease label), so
 * every split whose tail is a version NuGet accepts is returned and the index decides: only a real id is a package there.
 * A reading that is not a real package costs a lookup and answers "allowed", so it cannot outvote the one that is.
 */
function parseCdn(parts: string[]): ParsedPackage[] {
  const file = parts.at(-1) ?? "";
  if (parts.at(-2)?.toLowerCase() !== "packages" || !file.toLowerCase().endsWith(".nupkg")) return [];
  const tokens = file.slice(0, -".nupkg".length).split(".");
  const found: ParsedPackage[] = [];
  for (let i = 1; i < tokens.length; i++) {
    const version = tokens.slice(i).join(".");
    if (parseNugetVersion(version) === null) continue;
    const name = tokens.slice(0, i).join(".");
    if (name.length > MAX_ID_LENGTH || !NUGET_ID.test(name)) continue;
    found.push({ ecosystem: "nuget", namespace: null, name, version });
  }
  return found.length > MAX_CANDIDATES ? found.slice(0, MAX_CANDIDATES) : found;
}

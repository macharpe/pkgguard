import type { ParsedPackage } from "./types.js";

/** A NuGet id: letters, digits, `_`, and `.` or `-` between them. Unicode is legal, and the feed has ids that use it. */
const NUGET_ID = /^[\p{L}\p{N}\p{M}_]+(?:[.-][\p{L}\p{N}\p{M}_]+)*$/u;
/** The version as the flat container writes it: normalised, so no build metadata. Validated properly by the comparator. */
const NUGET_VERSION = /^\d[0-9A-Za-z.-]*$/;
const MAX_ID_LENGTH = 100;

function decode(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * NuGet downloads from the flat container: `/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg`.
 *
 * The id and the version are separate path segments and the file repeats both, so there is nothing to guess: the last three
 * segments are read and the file name must be exactly `{id}.{version}.nupkg`. That is a shape no other ecosystem's download
 * has, so a mirror's path prefix is tolerated without anchoring on a segment name. The flat container lowercases both, and a
 * client sends them that way, so the file name is compared case-insensitively. Total: never throws.
 */
export function parseNugetUrl(url: URL): ParsedPackage[] {
  const segments = url.pathname.split("/").map(decode);
  if (segments.some((s) => s === null)) return [];
  const parts = segments as string[];
  if (parts.length < 4) return [];
  const id = parts.at(-3) as string;
  const version = parts.at(-2) as string;
  const file = parts.at(-1) as string;
  if (id.length === 0 || id.length > MAX_ID_LENGTH || !NUGET_ID.test(id) || !NUGET_VERSION.test(version)) return [];
  if (file.toLowerCase() !== `${id}.${version}.nupkg`.toLowerCase()) return [];
  return [{ ecosystem: "nuget", namespace: null, name: id, version }];
}

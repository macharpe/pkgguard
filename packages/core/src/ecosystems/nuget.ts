import { parseNugetUrl } from "../parse/nuget.js";
import { compareNuget } from "../version/nuget.js";
import type { EcosystemSpec } from "./types.js";

/**
 * NuGet ids are case-insensitive, and the flat container lowercases them. OSV records the spelling it was given, and the
 * feed holds 33 ids under more than one, so both sides are lowercased and the advisories of every spelling merge.
 *
 * Only case is folded: `.`, `-` and `_` are different characters in an id. Unicode ids exist (malware that spells a name
 * with Cyrillic look-alikes), and lowercasing them agrees with .NET's `ToLowerInvariant` over every name in the feed.
 */
export function normalizeNugetName(name: string): string {
  return name.trim().toLowerCase();
}

export const nuget: EcosystemSpec = {
  id: "nuget",
  osvName: "NuGet",
  gatewayName: "nuget",
  purlType: "nuget",
  normalizeName: normalizeNugetName,
  purlName: (name) => name.toLowerCase(),
  compare: compareNuget,
  namespaceOf: () => null,
  // After lowercasing: lowercase or caseless letters, digits and marks, so a homoglyph malware id can be named.
  overrideNamePattern: /^[\p{Ll}\p{Lo}\p{N}_][\p{Ll}\p{Lo}\p{N}\p{M}_.-]*$/u,
  maxNameLength: 100,
  parse: parseNugetUrl,
};

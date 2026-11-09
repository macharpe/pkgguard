import { parseRubygemsUrl } from "../parse/rubygems.js";
import { compareGem } from "../version/gem.js";
import type { EcosystemSpec } from "./types.js";

/**
 * Lowercase only. RubyGems tells gems apart by case, and `-` and `_` are different characters, so folding them would
 * merge distinct gems: 23 pairs in OSV's feed differ only by that, such as `3scale-time-range` and `3scale-time_range`.
 * Lowercasing alone is safe: no two names in the feed collide under it.
 */
export function normalizeRubygemsName(name: string): string {
  return name.trim().toLowerCase();
}

export const rubygems: EcosystemSpec = {
  id: "rubygems",
  osvName: "RubyGems",
  // Measured: Gateway's API accepts "gem" and refuses "rubygems".
  gatewayName: "gem",
  purlType: "gem",
  normalizeName: normalizeRubygemsName,
  purlName: (name) => name.toLowerCase(),
  compare: compareGem,
  namespaceOf: () => null,
  overrideNamePattern: /^[a-z0-9][a-z0-9._-]*$/,
  maxNameLength: 128,
  parse: parseRubygemsUrl,
};

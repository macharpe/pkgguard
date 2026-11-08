import { parseCargoUrl } from "../parse/cargo.js";
import { compareSemver } from "../version/semver.js";
import type { EcosystemSpec } from "./types.js";

/**
 * crates.io treats a name case-insensitively and `-` and `_` as the same character, so `Serde_Json`, `serde-json`
 * and `serde_json` are one crate. OSV records the spelling it was given, so both sides are folded to one.
 */
export function normalizeCargoName(name: string): string {
  return name.trim().toLowerCase().replace(/_/g, "-");
}

export const cargo: EcosystemSpec = {
  id: "cargo",
  osvName: "crates.io",
  gatewayName: "cargo",
  purlType: "cargo",
  normalizeName: normalizeCargoName,
  purlName: (name) => name.toLowerCase(),
  compare: compareSemver,
  namespaceOf: () => null,
  // Matched after normalisation, so `_` has already become `-`.
  overrideNamePattern: /^[a-z0-9][a-z0-9-]*$/,
  maxNameLength: 64,
  parse: parseCargoUrl,
};

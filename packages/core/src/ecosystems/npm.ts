import { parseNpmUrl } from "../parse/npm.js";
import { compareSemver } from "../version/semver.js";
import type { EcosystemSpec } from "./types.js";

/** npm names are matched case-insensitively so a case variant cannot bypass a lookup. */
export function normalizeNpmName(name: string): string {
  return name.trim().toLowerCase();
}

export const npm: EcosystemSpec = {
  id: "npm",
  osvName: "npm",
  gatewayName: "npm",
  purlType: "npm",
  normalizeName: normalizeNpmName,
  purlName: (name) => name.toLowerCase(),
  compare: compareSemver,
  namespaceOf(name) {
    if (!name.startsWith("@")) return null;
    const slash = name.indexOf("/");
    return slash > 1 ? name.slice(0, slash) : null;
  },
  // A scope is optional; each part must start alphanumeric, so "..", "/x" and "a//b" can never be keys.
  overrideNamePattern: /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/,
  maxNameLength: 214,
  parse(url) {
    const pkg = parseNpmUrl(url);
    return pkg === null ? [] : [pkg];
  },
};

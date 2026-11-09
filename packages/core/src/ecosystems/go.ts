import { parseGoUrl } from "../parse/go.js";
import { compareGo } from "../version/go.js";
import type { EcosystemSpec } from "./types.js";

/** One element of a module path, as `parse/go.ts` has it: letters, digits and `-._~`, not starting or ending with a dot. */
const ELEMENT = "[A-Za-z0-9_~-](?:[A-Za-z0-9._~-]*[A-Za-z0-9_~-])?";

/**
 * A Go module path is case-sensitive, and the proxy keeps `github.com/bishopfox/sliver` and `github.com/BishopFox/sliver` apart
 * (eight such pairs are in OSV's feed), so the name is kept exactly: only surrounding whitespace is dropped. Folding case
 * would apply one module's advisory to another.
 */
export function normalizeGoName(name: string): string {
  return name.trim();
}

/**
 * Whether a module path can be downloaded from a proxy at all. The first element of a real one is a domain, so it has a dot.
 * OSV also lists `stdlib` and `toolchain`, which are not modules, and a few malformed names (`https://github.com/…`);
 * keeping them would only make the dashboard count advisories for packages nobody can fetch.
 */
export function isDownloadableGoName(name: string): boolean {
  return (name.split("/")[0] ?? "").includes(".");
}

export const go: EcosystemSpec = {
  id: "go",
  osvName: "Go",
  // Measured: Gateway's API accepts "golang" and refuses "go".
  gatewayName: "golang",
  purlType: "golang",
  normalizeName: normalizeGoName,
  // The purl spec lowercases a golang name, which would blur the pairs above; this is for display, so it keeps the case.
  purlName: (name) => name,
  pathNames: true,
  compare: compareGo,
  namespaceOf: () => null,
  inScope: isDownloadableGoName,
  // Slashes are safe in a key (npm scopes have one), and `.` and `..` cannot be an element: each starts and ends with a
  // character that is not a dot. The first element must be a domain.
  overrideNamePattern: new RegExp(`^(?=[^/]*\\.)${ELEMENT}(?:/${ELEMENT})*$`),
  maxNameLength: 255,
  parse: parseGoUrl,
};

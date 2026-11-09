import type { Ecosystem } from "../ecosystem-ids.js";
import type { ParsedPackage } from "../parse/types.js";

/** Everything that differs between one package ecosystem and another. One record per ecosystem, in `ecosystems/`. */
export interface EcosystemSpec {
  readonly id: Ecosystem;
  /** How OSV names the ecosystem: the bucket directory and the `ecosystem` field of a query. */
  readonly osvName: string;
  /** The value of Gateway's `pkg.ecosystem` selector. */
  readonly gatewayName: string;
  /** The package-url type, as in `pkg:npm/lodash@4.17.21`. */
  readonly purlType: string;
  /** The name as the registry treats it: the same package under any spelling gives the same string. */
  normalizeName(raw: string): string;
  /** The name as it appears in a package URL. Not trimmed, unlike `normalizeName`. */
  purlName(name: string): string;
  /**
   * True when the name is itself a path whose slashes are separators (a Go module path), so a package URL keeps them. For
   * every other ecosystem a slash in a name is just a character, and stays percent-encoded so the name remains one segment.
   */
  readonly pathNames?: boolean;
  /** -1, 0 or 1; null when either version cannot be parsed, which callers must read as "no match". */
  compare(a: string, b: string): -1 | 0 | 1 | null;
  /** The namespace part of a normalised name (an npm scope), or null. */
  namespaceOf(normalizedName: string): string | null;
  /**
   * Whether a normalised name is worth storing. Absent means every name is. Used to leave out entries the registry cannot
   * serve, so the dashboard counts advisories for packages that can be downloaded.
   */
  inScope?(normalizedName: string): boolean;
  /** What an administrator may type as a package name, after normalisation. */
  readonly overrideNamePattern: RegExp;
  readonly maxNameLength: number;
  /**
   * Candidate packages for a download URL: empty when it is not one of this ecosystem's downloads. A list rather
   * than one package because some file names cannot be split into a name and a version without guessing.
   */
  parse(url: URL): ParsedPackage[];
}

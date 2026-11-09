/**
 * NuGet version ordering, a port of `NuGet.Versioning` (`NuGetVersion` and `VersionComparer.VersionRelease`).
 *
 * In short: one to four numeric parts, so `1`, `1.0`, `1.0.0` and `1.0.0.0` are all equal; an optional `-` prerelease of
 * dot-separated labels; an optional `+` build, which is ignored.
 *
 * What differs from SemVer, and from what a first guess would be:
 * - the fourth numeric part (`6.8.5.1001`), and leading zeros in the numeric parts (`10.02.0` equals `10.2.0`);
 * - each numeric part must fit an Int32 (`2147483648.0.0` is refused), but a numeric prerelease label has no limit;
 * - a numeric prerelease label may not have a leading zero (`-01` is refused, `-0` is fine, `-0251-40` is a text label);
 * - text labels compare case-insensitively (`1.0.0-RC` equals `1.0.0-rc`), numbers below text, a shorter list below a
 *   longer one with the same start, and any prerelease below the release.
 *
 * Differs from NuGet in one deliberate way: surrounding whitespace is refused, where NuGet trims it, because whitespace in
 * a download URL or an advisory is a mistake to refuse, never a version to compare.
 */

const INT32_MAX = 2_147_483_647n;
/** One numeric part: digits only. Its size is checked afterwards, as a number. */
const NUMBER = /^\d+$/;
/** A prerelease label or a build identifier: letters, digits and hyphens. */
const IDENTIFIER = /^[0-9A-Za-z-]+$/;

export interface NugetVersion {
  readonly parts: readonly [bigint, bigint, bigint, bigint];
  readonly labels: readonly string[];
}

/** The parts and prerelease labels of a version, or null when it is not a version. Mirrors `NuGetVersion.TryParse`. */
export function parseNugetVersion(raw: string): NugetVersion | null {
  const plus = raw.indexOf("+");
  const withoutBuild = plus === -1 ? raw : raw.slice(0, plus);
  if (plus !== -1 && !isDotted(raw.slice(plus + 1))) return null;

  const dash = withoutBuild.indexOf("-");
  const numbers = dash === -1 ? withoutBuild : withoutBuild.slice(0, dash);
  const labels = dash === -1 ? [] : withoutBuild.slice(dash + 1).split(".");

  const segments = numbers.split(".");
  if (segments.length > 4) return null;
  const parts: bigint[] = [];
  for (const segment of segments) {
    if (!NUMBER.test(segment)) return null;
    const value = BigInt(segment);
    if (value > INT32_MAX) return null;
    parts.push(value);
  }
  while (parts.length < 4) parts.push(0n);

  if (dash !== -1) {
    for (const label of labels) {
      if (!IDENTIFIER.test(label)) return null;
      if (NUMBER.test(label) && label.length > 1 && label.startsWith("0")) return null;
    }
  }
  return { parts: parts as unknown as NugetVersion["parts"], labels };
}

function isDotted(text: string): boolean {
  return text.split(".").every((identifier) => IDENTIFIER.test(identifier));
}

const upper = (label: string): string => label.toUpperCase();

function compareLabel(a: string, b: string): -1 | 0 | 1 {
  const aNumeric = NUMBER.test(a);
  const bNumeric = NUMBER.test(b);
  if (aNumeric && bNumeric) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x === y ? 0 : x < y ? -1 : 1;
  }
  if (aNumeric) return -1;
  if (bNumeric) return 1;
  const x = upper(a);
  const y = upper(b);
  return x === y ? 0 : x < y ? -1 : 1;
}

/** -1, 0 or 1, or null when either side is not a version. Mirrors `VersionComparer.VersionRelease`. */
export function compareNuget(a: string, b: string): -1 | 0 | 1 | null {
  const x = parseNugetVersion(a);
  const y = parseNugetVersion(b);
  if (x === null || y === null) return null;
  for (let i = 0; i < 4; i++) {
    const lhs = x.parts[i] as bigint;
    const rhs = y.parts[i] as bigint;
    if (lhs !== rhs) return lhs < rhs ? -1 : 1;
  }
  if (x.labels.length === 0 && y.labels.length === 0) return 0;
  if (x.labels.length === 0) return 1;
  if (y.labels.length === 0) return -1;
  const shared = Math.min(x.labels.length, y.labels.length);
  for (let i = 0; i < shared; i++) {
    const result = compareLabel(x.labels[i] as string, y.labels[i] as string);
    if (result !== 0) return result;
  }
  return x.labels.length === y.labels.length ? 0 : x.labels.length < y.labels.length ? -1 : 1;
}

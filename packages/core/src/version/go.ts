/**
 * Go module version ordering, a port of `golang.org/x/mod/semver`.
 *
 * It is SemVer 2.0 with one addition Go makes: `v1` and `v1.2` are valid and mean `v1.0.0` and `v1.2.0`. OSV records Go
 * versions without the leading `v` that Go and the proxy URL write, and a few of its range boundaries are shorthand
 * (`4.0`, `0.46`, `136`), which the SemVer comparator cannot read and so would leave inert. A leading `v` is accepted, once,
 * and optional.
 *
 * Rules, as Go has them:
 * - numeric parts have no leading zeros, and a shorthand version has no prerelease or build (`1.2-rc1` is not a version);
 * - a prerelease is dot-separated identifiers of letters, digits and hyphens, a numeric one without a leading zero;
 * - numbers compare as numbers, and sort below text; text compares as ASCII, so case matters (`RC` sorts below `rc`);
 * - a prerelease sorts below the release, and a shorter list below a longer one with the same start;
 * - build metadata (`+incompatible`) is ignored.
 */

const DIGITS = /^\d+$/;
const IDENTIFIER = /^[0-9A-Za-z-]+$/;
const BUILD_IDENTIFIER = /^[0-9A-Za-z-]+$/;

export interface GoVersion {
  readonly major: bigint;
  readonly minor: bigint;
  readonly patch: bigint;
  readonly prerelease: readonly string[];
}

/** One numeric part: digits, and a leading zero only if that is the whole part. */
function number(part: string): bigint | null {
  if (!DIGITS.test(part) || (part.length > 1 && part.startsWith("0"))) return null;
  return BigInt(part);
}

/** The parts of a version, or null when it is not one. Mirrors `semver.IsValid`, with the `v` optional. */
export function parseGoVersion(raw: string): GoVersion | null {
  const text = raw.startsWith("v") ? raw.slice(1) : raw;

  const plus = text.indexOf("+");
  const withoutBuild = plus === -1 ? text : text.slice(0, plus);
  if (plus !== -1) {
    const build = text.slice(plus + 1).split(".");
    if (!build.every((identifier) => BUILD_IDENTIFIER.test(identifier))) return null;
  }

  const dash = withoutBuild.indexOf("-");
  const numbers = dash === -1 ? withoutBuild : withoutBuild.slice(0, dash);
  const prerelease = dash === -1 ? [] : withoutBuild.slice(dash + 1).split(".");

  const segments = numbers.split(".");
  if (segments.length > 3) return null;
  // `v1` and `v1.2` are shorthand, and a shorthand has nowhere to hang a prerelease or a build.
  if (segments.length < 3 && (dash !== -1 || plus !== -1)) return null;
  const values = segments.map(number);
  if (values.some((value) => value === null)) return null;
  const [major, minor, patch] = [values[0] as bigint, (values[1] ?? 0n) as bigint, (values[2] ?? 0n) as bigint];

  for (const identifier of prerelease) {
    if (!IDENTIFIER.test(identifier)) return null;
    if (DIGITS.test(identifier) && identifier.length > 1 && identifier.startsWith("0")) return null;
  }
  return { major, minor, patch, prerelease };
}

function compareIdentifier(a: string, b: string): -1 | 0 | 1 {
  if (a === b) return 0;
  const aNumeric = DIGITS.test(a);
  const bNumeric = DIGITS.test(b);
  if (aNumeric !== bNumeric) return aNumeric ? -1 : 1;
  if (aNumeric) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x === y ? 0 : x < y ? -1 : 1;
  }
  return a < b ? -1 : 1;
}

/** -1, 0 or 1, or null when either side is not a version. Mirrors `semver.Compare`. */
export function compareGo(a: string, b: string): -1 | 0 | 1 | null {
  const x = parseGoVersion(a);
  const y = parseGoVersion(b);
  if (x === null || y === null) return null;
  for (const part of ["major", "minor", "patch"] as const) {
    if (x[part] !== y[part]) return x[part] < y[part] ? -1 : 1;
  }
  if (x.prerelease.length === 0 && y.prerelease.length === 0) return 0;
  if (x.prerelease.length === 0) return 1;
  if (y.prerelease.length === 0) return -1;
  const shared = Math.min(x.prerelease.length, y.prerelease.length);
  for (let i = 0; i < shared; i++) {
    const result = compareIdentifier(x.prerelease[i] as string, y.prerelease[i] as string);
    if (result !== 0) return result;
  }
  return x.prerelease.length === y.prerelease.length ? 0 : x.prerelease.length < y.prerelease.length ? -1 : 1;
}

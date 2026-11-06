import semver from "semver";

/** -1 | 0 | 1, or null when either side is not a valid SemVer version. */
export function compareSemver(a: string, b: string): -1 | 0 | 1 | null {
  const x = semver.parse(a.trim());
  const y = semver.parse(b.trim());
  if (!x || !y) return null;
  return x.compare(y);
}

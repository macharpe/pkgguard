/**
 * RubyGems version ordering, a port of `Gem::Version`.
 *
 * What it is, in short: a version is split into runs of digits and runs of letters (`1.0.0.pre.1` is 1, 0, 0, "pre", 1);
 * a letter run makes it a prerelease, and sorts below any number; trailing zeros do not matter (`1.0` equals `1`); and a
 * hyphen is read as `.pre.` (`1.0-rc1` is `1.0.pre.rc1`).
 *
 * Numbers are BigInt, because a Ruby integer has no 2^53 ceiling and a version string above it is legal. Letter runs are
 * compared as plain strings, as Ruby does (case-sensitive, ASCII).
 *
 * Differs from Ruby in one deliberate way: a blank string is unreadable here (Ruby reads it as "0"), because a blank
 * version in a download URL or an advisory is a mistake to refuse, never a version to compare.
 */

/** `Gem::Version::ANCHORED_VERSION_PATTERN`, with Ruby's `\s` written out, since JavaScript's matches more. */
const CORRECT = /^[ \t\r\n\f\v]*([0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)[ \t\r\n\f\v]*$/;

type Segment = bigint | string;

function dropTrailingZeros(segments: Segment[]): Segment[] {
  let end = segments.length;
  while (end > 0 && segments[end - 1] === 0n) end--;
  return segments.slice(0, end);
}

/** The canonical segments of a version, or null when it is not a version. Mirrors `Gem::Version#canonical_segments`. */
export function parseGemVersion(raw: string): Segment[] | null {
  const match = CORRECT.exec(raw);
  if (match === null) return null;
  const text = (match[1] as string).replaceAll("-", ".pre.");
  const segments: Segment[] = (text.match(/[0-9]+|[a-z]+/gi) ?? []).map((part) => (/^\d+$/.test(part) ? BigInt(part) : part));
  const firstString = segments.findIndex((s) => typeof s === "string");
  const numeric = firstString === -1 ? segments : segments.slice(0, firstString);
  const letters = firstString === -1 ? [] : segments.slice(firstString);
  return [...dropTrailingZeros(numeric), ...dropTrailingZeros(letters)];
}

/** -1, 0 or 1, or null when either side is not a version. Mirrors `Gem::Version#<=>`. */
export function compareGem(a: string, b: string): -1 | 0 | 1 | null {
  const x = parseGemVersion(a);
  const y = parseGemVersion(b);
  if (x === null || y === null) return null;
  const limit = Math.max(x.length, y.length);
  for (let i = 0; i < limit; i++) {
    const lhs = x[i] ?? 0n;
    const rhs = y[i] ?? 0n;
    if (lhs === rhs) continue;
    if (typeof lhs === "string" && typeof rhs !== "string") return -1;
    if (typeof lhs !== "string" && typeof rhs === "string") return 1;
    return lhs < rhs ? -1 : 1;
  }
  return 0;
}

/**
 * OSV timestamps carry up to nanoseconds ("2026-11-06T11:30:04.463693441Z") and sometimes none ("…04Z").
 * Plain string comparison is wrong for that mix: "04.4Z" sorts before "04Z" because '.' < 'Z'.
 * Padding the fraction to nine digits makes lexical order equal chronological order.
 */
const ISO = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/;

export function normalizeIso(value: string): string | null {
  const match = ISO.exec(value.trim());
  if (!match) return null;
  const [, date, time, fraction = ""] = match as unknown as [string, string, string, string | undefined];
  if (Number.isNaN(Date.parse(`${date}T${time}Z`))) return null;
  return `${date}T${time}.${fraction.padEnd(9, "0")}Z`;
}

/** True when `value` is at or after `since`. Anything unparseable counts as newer, so it is re-fetched rather than skipped. */
export function isAtOrAfter(value: string, since: string): boolean {
  const a = normalizeIso(value);
  const b = normalizeIso(since);
  if (a === null || b === null) return true;
  return a >= b;
}

export function maxIso(values: readonly string[]): string | null {
  let best: string | null = null;
  let bestNorm: string | null = null;
  for (const value of values) {
    const norm = normalizeIso(value);
    if (norm !== null && (bestNorm === null || norm > bestNorm)) {
      best = value;
      bestNorm = norm;
    }
  }
  return best;
}

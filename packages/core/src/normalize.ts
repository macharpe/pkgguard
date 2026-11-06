export type Ecosystem = "npm" | "pypi";

/** KV keys are capped at 512 bytes. */
const MAX_KEY_BYTES = 512;

/** npm names are matched case-insensitively so a case variant cannot bypass a lookup. */
export function normalizeNpmName(name: string): string {
  return name.trim().toLowerCase();
}

/** PEP 503: lowercase, runs of `-`, `_`, `.` collapse to a single `-`. */
export function normalizePypiName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

export function normalizeName(ecosystem: Ecosystem, name: string): string {
  return ecosystem === "npm" ? normalizeNpmName(name) : normalizePypiName(name);
}

/** Returns null when the key would exceed the KV limit. Fail-open: the caller treats null as "no match". */
export function kvKey(ecosystem: Ecosystem, name: string): string | null {
  const key = `${ecosystem}:${normalizeName(ecosystem, name)}`;
  return new TextEncoder().encode(key).length <= MAX_KEY_BYTES ? key : null;
}

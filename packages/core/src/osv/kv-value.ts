import type { KvEntry } from "./index-entry.js";

/** Short-lived marker: a live OSV lookup found no advisories for this package. */
export interface KvNegative {
  v: 1;
  n: true;
  u: string;
}

export type KvValue = KvEntry | KvNegative;

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function isAdvisoryList(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.every((a) => isObject(a) && typeof a["id"] === "string" && Array.isArray(a["r"]) && Array.isArray(a["v"]))
  );
}

/** Validates an untrusted KV value. Null means corrupt or from an unknown schema version. */
export function parseKvValue(raw: unknown): KvValue | null {
  if (!isObject(raw) || raw["v"] !== 1 || typeof raw["u"] !== "string") return null;
  if (raw["n"] === true) return raw as unknown as KvNegative;
  if (!isAdvisoryList(raw["m"]) || !isAdvisoryList(raw["c"])) return null;
  return raw as unknown as KvEntry;
}

export const isNegative = (value: KvValue): value is KvNegative => "n" in value;

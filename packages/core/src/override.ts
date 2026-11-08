import type { Ecosystem } from "./ecosystem-ids.js";
import { normalizeName } from "./normalize.js";
import { isVersionAffected } from "./osv/match.js";

export type OverrideMode = "block" | "allow";

/** Value stored under `override:<mode>:<ecosystem>:<normalized-name>`. */
export interface KvOverride {
  v: 1;
  /** Exact versions the override covers. Null covers every version. */
  versions: string[] | null;
  note?: string;
}

const MAX_KEY_BYTES = 512;

export function overrideKey(mode: OverrideMode, ecosystem: Ecosystem, name: string): string | null {
  const key = `override:${mode}:${ecosystem}:${normalizeName(ecosystem, name)}`;
  return new TextEncoder().encode(key).length <= MAX_KEY_BYTES ? key : null;
}

export function parseOverride(raw: unknown): KvOverride | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const value = raw as Record<string, unknown>;
  if (value["v"] !== 1) return null;
  const versions = value["versions"];
  if (versions === null) return raw as KvOverride;
  if (Array.isArray(versions) && versions.every((x) => typeof x === "string")) return raw as KvOverride;
  return null;
}

export function overrideApplies(ecosystem: Ecosystem, override: KvOverride, version: string): boolean {
  if (override.versions === null) return true;
  return isVersionAffected(ecosystem, { r: [], v: override.versions }, version);
}

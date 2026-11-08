import { ECOSYSTEMS } from "./ecosystems/index.js";
import type { Ecosystem } from "./ecosystem-ids.js";

export type { Ecosystem } from "./ecosystem-ids.js";
export { normalizeNpmName, normalizePypiName } from "./ecosystems/index.js";

/** KV keys are capped at 512 bytes. */
const MAX_KEY_BYTES = 512;

export function normalizeName(ecosystem: Ecosystem, name: string): string {
  return ECOSYSTEMS[ecosystem].normalizeName(name);
}

/** Returns null when the key would exceed the KV limit. Fail-open: the caller treats null as "no match". */
export function kvKey(ecosystem: Ecosystem, name: string): string | null {
  const key = `${ecosystem}:${normalizeName(ecosystem, name)}`;
  return new TextEncoder().encode(key).length <= MAX_KEY_BYTES ? key : null;
}

import { ENABLED_ECOSYSTEMS, type Ecosystem } from "../ecosystem-ids.js";
import { npm } from "./npm.js";
import { pypi } from "./pypi.js";
import type { EcosystemSpec } from "./types.js";

export type { EcosystemSpec } from "./types.js";
export { normalizeNpmName } from "./npm.js";
export { normalizePypiName } from "./pypi.js";

/** Typed as a full record, so defining an id without a spec here does not compile. */
export const ECOSYSTEMS: Readonly<Record<Ecosystem, EcosystemSpec>> = { npm, pypi };

export const ecosystemSpec = (ecosystem: Ecosystem): EcosystemSpec => ECOSYSTEMS[ecosystem];

/** The enabled ecosystem OSV calls `osvName`, or null. A lookup by search, so an inherited key such as "constructor" cannot match. */
export function ecosystemFromOsvName(osvName: unknown): Ecosystem | null {
  return typeof osvName === "string" ? (ENABLED_ECOSYSTEMS.find((id) => ECOSYSTEMS[id].osvName === osvName) ?? null) : null;
}

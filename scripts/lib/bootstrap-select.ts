import { ECOSYSTEMS, ECOSYSTEM_IDS, ENABLED_ECOSYSTEMS, type Ecosystem } from "../../packages/core/src/index.js";

export interface Selected {
  ours: Ecosystem;
  /** OSV's name for it: the bucket directory and the zip's name. */
  osv: string;
}

const selected = (id: Ecosystem): Selected => ({ ours: id, osv: ECOSYSTEMS[id].osvName });

/**
 * Which ecosystems a bootstrap command works on. With no `--ecosystem` it is the enabled ones, the whole index of a
 * fresh database. Naming one (by id or by OSV's name for it) selects that alone, and it may be an ecosystem that is
 * defined but not yet enabled: its data goes in first, and enabling comes after. A flag with no value is an error,
 * not "all": a forgotten argument must not turn a one-ecosystem load into a full one.
 */
export function selectEcosystems(requested: string | undefined): { ecosystems: Selected[]; explicit: boolean } {
  if (requested === undefined) return { ecosystems: ENABLED_ECOSYSTEMS.map(selected), explicit: false };
  const id = ECOSYSTEM_IDS.find((candidate) => candidate === requested || ECOSYSTEMS[candidate].osvName === requested);
  if (id === undefined) {
    const valid = ECOSYSTEM_IDS.map((candidate) => `${candidate} (OSV: ${ECOSYSTEMS[candidate].osvName})`).join(", ");
    throw new Error(`--ecosystem must name one of: ${valid}; got ${JSON.stringify(requested)}`);
  }
  return { ecosystems: [selected(id)], explicit: true };
}

/** Each selection gets its own directory, so a one-ecosystem run cannot overwrite the full index or share its checkpoint. */
export const defaultOutName = (explicit: boolean, ecosystems: readonly Selected[]): string =>
  explicit && ecosystems[0] ? `out-${ecosystems[0].ours}` : "out";

/** Reads the ecosystems out of `wrangler d1 execute --json` for `SELECT ecosystem FROM sync_state`. Throws when it cannot tell. */
export function parseSyncStateIds(stdout: string): string[] {
  const parsed: unknown = JSON.parse(stdout);
  if (!Array.isArray(parsed)) throw new Error("unexpected output from the sync_state query");
  const ids: string[] = [];
  for (const statement of parsed as Array<{ results?: unknown }>) {
    if (!Array.isArray(statement.results)) throw new Error("unexpected output from the sync_state query");
    for (const row of statement.results as Array<{ ecosystem?: unknown }>) if (typeof row.ecosystem === "string") ids.push(row.ecosystem);
  }
  return ids;
}

/**
 * What output written before the stats recorded its ecosystems contained: npm and PyPI, the only two that existed.
 * It is a fixed list, not the enabled set, which grows: an old directory must never be taken for a newer, larger one.
 */
const LEGACY_OUTPUT: readonly string[] = ["npm", "pypi"];

/**
 * A generated directory must be for the ecosystems being loaded. One written for a single ecosystem, loaded as a
 * fresh database, would leave the others silently missing; the reverse would load more than was asked for.
 */
export function assertGeneratedFor(recorded: unknown, wanted: readonly Selected[]): void {
  const have = Array.isArray(recorded) ? recorded.map(String) : [...LEGACY_OUTPUT];
  const want = wanted.map((entry) => entry.ours);
  if (have.length !== want.length || !want.every((id) => have.includes(id))) {
    throw new Error(`this directory was generated for [${have.join(", ")}], but this load is for [${want.join(", ")}]: generate again with the same --ecosystem`);
  }
}

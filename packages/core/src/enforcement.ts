/**
 * What the filter Worker says about its own enforcement, so the dashboard can show what is actually running
 * instead of what the admin Worker was deployed with. Pure TypeScript: the filter writes it, the admin Worker reads it.
 *
 * It lives in the index namespace under a `meta:` key. Index keys are `<ecosystem id>:<name>` and no ecosystem is
 * called `meta`, so the two cannot collide (a test pins that).
 */

import { ECOSYSTEM_IDS, type Ecosystem } from "./ecosystem-ids.js";

export const ENFORCEMENT_KEY = "meta:enforcement";

/** An isolate repeats its report at most this often. A busy Worker therefore keeps the report fresh without hammering one KV key. */
export const ENFORCEMENT_REFRESH_MS = 60 * 60 * 1000;

/** After a failed read or write an isolate waits this long before trying again, so a KV outage costs one attempt a minute, not one a request. */
export const ENFORCEMENT_RETRY_MS = 60 * 1000;

export interface EnforcementReport {
  enforce: boolean;
  /** Ecosystems that never block, in registry order. */
  observeOnly: Ecosystem[];
  reportedAt: string;
}

export interface EnforcementSettings {
  enforce: boolean;
  observeOnly: ReadonlySet<Ecosystem>;
}

/** Built from the parsed settings, so an unknown id in the `OBSERVE_ONLY` variable can never appear in it. */
export function enforcementReport(settings: EnforcementSettings, reportedAt: string): EnforcementReport {
  return { enforce: settings.enforce, observeOnly: ECOSYSTEM_IDS.filter((id) => settings.observeOnly.has(id)), reportedAt };
}

/** Whether two reports describe the same behaviour. The time is not part of that. */
export const sameEnforcement = (a: Pick<EnforcementReport, "enforce" | "observeOnly">, b: Pick<EnforcementReport, "enforce" | "observeOnly">): boolean =>
  a.enforce === b.enforce && a.observeOnly.length === b.observeOnly.length && a.observeOnly.every((id, i) => id === b.observeOnly[i]);

/**
 * Validates an untrusted KV value. Null means missing, corrupt or the wrong shape, and must never be read as "enforcement is off".
 * Unknown ecosystem ids are dropped rather than failing the whole report, since an id this build does not know is no reason to hide the rest.
 */
export function parseEnforcement(raw: unknown): EnforcementReport | null {
  if (typeof raw !== "object" || raw === null) return null;
  const { enforce, observeOnly, reportedAt } = raw as Record<string, unknown>;
  if (typeof enforce !== "boolean" || !Array.isArray(observeOnly) || typeof reportedAt !== "string") return null;
  if (Number.isNaN(Date.parse(reportedAt))) return null;
  // Filtering the registry by what was listed is what drops an id this build does not know.
  const listed = new Set<unknown>(observeOnly);
  return { enforce, observeOnly: ECOSYSTEM_IDS.filter((id) => listed.has(id)), reportedAt };
}

/** Parses the stored text. Text that is not JSON is as good as missing. */
export function parseEnforcementText(text: string | null): EnforcementReport | null {
  if (text === null) return null;
  try {
    return parseEnforcement(JSON.parse(text));
  } catch {
    return null;
  }
}

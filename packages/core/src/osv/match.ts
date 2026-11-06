import type { Ecosystem } from "../normalize.js";
import { compareVersions } from "../version/index.js";
import type { OsvEvent } from "./types.js";

/** What an advisory says about one package. `all` means every version is affected. */
export interface AffectedSpec {
  /** One event list per non-GIT range. */
  r: OsvEvent[][];
  /** Explicitly listed affected versions. */
  v: string[];
  all?: true;
}

type Kind = "introduced" | "fixed" | "last_affected";
interface TypedEvent {
  kind: Kind;
  version: string;
}

const KIND_ORDER: Record<Kind, number> = { introduced: 0, fixed: 1, last_affected: 1 };

function typedEvents(events: OsvEvent[]): TypedEvent[] {
  const out: TypedEvent[] = [];
  for (const event of events) {
    if (typeof event.introduced === "string") out.push({ kind: "introduced", version: event.introduced });
    else if (typeof event.fixed === "string") out.push({ kind: "fixed", version: event.fixed });
    else if (typeof event.last_affected === "string") out.push({ kind: "last_affected", version: event.last_affected });
  }
  return out;
}

/**
 * Evaluates one OSV range per the OSV spec: sort events ascending, then walk them.
 * `introduced` at or below the version turns affected on; `fixed` at or below it,
 * or `last_affected` strictly below it, turns it off. `introduced: "0"` is the beginning of time.
 * Returns false (never throws) when any version involved cannot be parsed.
 */
export function inRange(ecosystem: Ecosystem, events: OsvEvent[], version: string): boolean {
  const list = typedEvents(events);
  if (list.length === 0) return false;
  // `introduced: "0"` never compares, so an unparseable target would otherwise slip through.
  if (compareVersions(ecosystem, version, version) === null) return false;

  let unparseable = false;
  const cmp = (a: string, b: string): number => {
    const r = compareVersions(ecosystem, a, b);
    if (r === null) {
      unparseable = true;
      return 0;
    }
    return r;
  };

  const sorted = [...list].sort((a, b) => {
    if (a.kind === "introduced" && a.version === "0") return b.kind === "introduced" && b.version === "0" ? 0 : -1;
    if (b.kind === "introduced" && b.version === "0") return 1;
    return cmp(a.version, b.version) || KIND_ORDER[a.kind] - KIND_ORDER[b.kind];
  });

  let affected = false;
  for (const event of sorted) {
    if (event.kind === "introduced") {
      if (event.version === "0" || cmp(version, event.version) >= 0) affected = true;
    } else if (event.kind === "fixed") {
      if (cmp(version, event.version) >= 0) affected = false;
    } else if (cmp(version, event.version) > 0) {
      affected = false;
    }
  }
  return unparseable ? false : affected;
}

/** True when `version` is covered by the spec. An unparseable version matches only an explicit string match or `all`. */
export function isVersionAffected(ecosystem: Ecosystem, spec: AffectedSpec, version: string): boolean {
  if (spec.all) return true;
  if (spec.v.some((listed) => listed === version || compareVersions(ecosystem, listed, version) === 0)) return true;
  return spec.r.some((events) => inRange(ecosystem, events, version));
}

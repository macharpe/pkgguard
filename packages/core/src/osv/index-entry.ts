import type { Ecosystem } from "../normalize.js";
import type { Advisory } from "./distill.js";
import { isVersionAffected, type AffectedSpec } from "./match.js";

export interface KvAdvisory extends AffectedSpec {
  id: string;
  sev?: string;
}

/** Value stored under `<ecosystem>:<normalized-name>` in the hot-path KV namespace. */
export interface KvEntry {
  v: 1;
  m: KvAdvisory[];
  c: KvAdvisory[];
  u: string;
}

export interface Verdict {
  malware: string[];
  vulnerabilities: Array<{ id: string; severity: string | null }>;
}

/** Withdrawn advisories are excluded. Returns null when nothing remains, so the key can be deleted. */
export function buildKvEntry(advisories: Advisory[], updated: string): KvEntry | null {
  const entry: KvEntry = { v: 1, m: [], c: [], u: updated };
  for (const advisory of advisories) {
    if (advisory.withdrawn) continue;
    const item: KvAdvisory = { id: advisory.osvId, ...advisory.spec };
    if (advisory.severity) item.sev = advisory.severity;
    (advisory.kind === "malware" ? entry.m : entry.c).push(item);
  }
  entry.m.sort((a, b) => a.id.localeCompare(b.id));
  entry.c.sort((a, b) => a.id.localeCompare(b.id));
  return entry.m.length + entry.c.length === 0 ? null : entry;
}

/** The hot-path decision: which advisories in this entry apply to this exact version. */
export function evaluate(ecosystem: Ecosystem, entry: KvEntry, version: string): Verdict {
  return {
    malware: entry.m.filter((a) => isVersionAffected(ecosystem, a, version)).map((a) => a.id),
    vulnerabilities: entry.c
      .filter((a) => isVersionAffected(ecosystem, a, version))
      .map((a) => ({ id: a.id, severity: a.sev ?? null })),
  };
}

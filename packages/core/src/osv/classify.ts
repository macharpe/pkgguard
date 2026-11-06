import type { AdvisoryKind, OsvRecord } from "./types.js";

/**
 * CWE-506 Embedded Malicious Code, CWE-507 Trojan Horse, CWE-510 Trapdoor,
 * CWE-511 Logic/Time Bomb, CWE-912 Hidden Functionality.
 */
export const MALWARE_CWES: ReadonlySet<string> = new Set([
  "CWE-506",
  "CWE-507",
  "CWE-510",
  "CWE-511",
  "CWE-912",
]);

const MAL_PREFIX = "MAL-";

export function collectCweIds(record: OsvRecord): string[] {
  const found = new Set<string>();
  for (const cwe of record.database_specific?.cwe_ids ?? []) {
    if (typeof cwe === "string") found.add(cwe);
  }
  for (const affected of record.affected ?? []) {
    for (const cwe of affected.database_specific?.cwes ?? []) {
      if (typeof cwe?.cweId === "string") found.add(cwe.cweId);
    }
  }
  return [...found];
}

/**
 * A record is malware when its ID or any alias starts with `MAL-`, or it carries
 * one of the malware CWEs. The `MAL-` prefix alone is not sufficient: human-reviewed
 * GHSA records such as event-stream have no `MAL-` ID. No summary-text heuristics.
 */
export function classify(record: OsvRecord): AdvisoryKind {
  if (record.id.startsWith(MAL_PREFIX)) return "malware";
  if ((record.aliases ?? []).some((alias) => alias.startsWith(MAL_PREFIX))) return "malware";
  if (collectCweIds(record).some((cwe) => MALWARE_CWES.has(cwe))) return "malware";
  return "vulnerability";
}

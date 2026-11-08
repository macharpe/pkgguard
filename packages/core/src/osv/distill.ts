import type { Ecosystem } from "../ecosystem-ids.js";
import { ECOSYSTEMS, ecosystemFromOsvName } from "../ecosystems/index.js";
import { normalizeName } from "../normalize.js";
import { classify, collectCweIds } from "./classify.js";
import type { AffectedSpec } from "./match.js";
import type { AdvisoryKind, OsvRecord } from "./types.js";

/** One row per (ecosystem, osv_id, package_name). A single OSV record can affect several packages. */
export interface Advisory {
  ecosystem: Ecosystem;
  osvId: string;
  /** Normalized, including the npm scope — identical to the KV key suffix. */
  packageName: string;
  namespace: string | null;
  kind: AdvisoryKind;
  severity: string | null;
  summary: string | null;
  cweIds: string[];
  spec: AffectedSpec;
  withdrawn: boolean;
  modified: string;
}

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MODERATE", "LOW"]);

function severityOf(record: OsvRecord): string | null {
  const raw = record.database_specific?.severity;
  const upper = typeof raw === "string" ? raw.toUpperCase() : "";
  return SEVERITIES.has(upper) ? upper : null;
}

/**
 * Turns an OSV record into advisory rows for the ecosystems in scope.
 * Multiple `affected[]` entries for one package are merged. GIT ranges are dropped.
 * Total for well-formed input; entries without a usable package are skipped.
 */
export function distill(record: OsvRecord): Advisory[] {
  const kind = classify(record);
  const merged = new Map<string, Advisory>();

  for (const affected of record.affected ?? []) {
    const ecosystem = ecosystemFromOsvName(affected.package?.ecosystem);
    const rawName = affected.package?.name;
    if (!ecosystem || typeof rawName !== "string" || rawName.trim() === "") continue;

    const packageName = normalizeName(ecosystem, rawName);
    const key = `${ecosystem}\u0000${packageName}`;
    let row = merged.get(key);
    if (!row) {
      row = {
        ecosystem,
        osvId: record.id,
        packageName,
        namespace: ECOSYSTEMS[ecosystem].namespaceOf(packageName),
        kind,
        severity: severityOf(record),
        summary: record.summary ?? null,
        cweIds: collectCweIds(record),
        spec: { r: [], v: [] },
        withdrawn: typeof record.withdrawn === "string",
        modified: record.modified,
      };
      merged.set(key, row);
    }

    const ranges = (affected.ranges ?? []).filter((range) => range.type !== "GIT");
    for (const range of ranges) row.spec.r.push(range.events);
    for (const version of affected.versions ?? []) {
      if (typeof version === "string" && !row.spec.v.includes(version)) row.spec.v.push(version);
    }

    // No ranges and no versions at all: for malware that means the whole package.
    const declaredNothing = (affected.ranges ?? []).length === 0 && (affected.versions ?? []).length === 0;
    if (declaredNothing && kind === "malware") row.spec.all = true;
  }

  return [...merged.values()];
}

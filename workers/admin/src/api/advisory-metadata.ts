import { parseCvssRating } from "@pkgguard/core";
import type { AdvisoryRow, DetectionAdvisory, DetectionRow } from "../api-types.js";
import type { Env } from "../env.js";

export type StoredAdvisory = Omit<AdvisoryRow, "cvss"> & { cvss_json: string | null };

export function readAdvisory(row: StoredAdvisory): AdvisoryRow {
  const { cvss_json, ...advisory } = row;
  return { ...advisory, cvss: parseCvssRating(cvss_json) };
}

/** Requested (ecosystem, package, id) triples per statement: one JSON parameter each, so D1's 100-parameter limit never applies, and the value stays small. */
const TRIPLES_PER_STATEMENT = 250;

type Wanted = { ecosystem: string; name: string; id: string };
type Stored = StoredAdvisory & { withdrawn: number };

const idsOf = (row: DetectionRow): string[] => [...new Set((row.osv_ids ?? "").split(",").filter(Boolean))];
const key = (ecosystem: string, name: string, id: string): string => JSON.stringify([ecosystem, name, id]);

/** Exported so the query-plan test validates the production query, not a copy of it. */
export const METADATA_SQL =
  "SELECT a.ecosystem, a.package_name, a.osv_id, a.kind, a.severity, a.summary, a.cvss_json, a.withdrawn " +
  "FROM json_each(?) AS requested JOIN advisories AS a " +
  "ON a.ecosystem = json_extract(requested.value, '$.ecosystem') " +
  "AND a.package_name = json_extract(requested.value, '$.name') " +
  "AND a.osv_id = json_extract(requested.value, '$.id')";

async function lookup(env: Env, wanted: Wanted[]): Promise<Map<string, Stored>> {
  const found = new Map<string, Stored>();
  if (wanted.length === 0) return found;
  const statement = env.DB.prepare(METADATA_SQL);
  const batches: D1PreparedStatement[] = [];
  for (let i = 0; i < wanted.length; i += TRIPLES_PER_STATEMENT) batches.push(statement.bind(JSON.stringify(wanted.slice(i, i + TRIPLES_PER_STATEMENT))));
  for (const { results } of await env.DB.batch<Stored>(batches)) {
    for (const row of results) found.set(key(row.ecosystem, row.package_name, row.osv_id), row);
  }
  return found;
}

/**
 * Enrich only the recorded matching IDs, never unrelated advisories for another version or package.
 * This is current index metadata, not evidence of what was known when the download happened, and it is cosmetic:
 * if the lookup fails the feed is returned without it (`advisories` absent) rather than failing the triage view.
 */
export async function enrichDetections(env: Env, rows: DetectionRow[]): Promise<DetectionRow[]> {
  try {
    const wanted = new Map<string, Wanted>();
    for (const row of rows) {
      for (const id of idsOf(row)) wanted.set(key(row.ecosystem, row.package_name, id), { ecosystem: row.ecosystem, name: row.package_name, id });
    }
    const metadata = await lookup(env, [...wanted.values()]);
    return rows.map((row) => ({
      ...row,
      advisories: idsOf(row).map((id): DetectionAdvisory => {
        const stored = metadata.get(key(row.ecosystem, row.package_name, id));
        // A withdrawn advisory keeps its status but loses its severity: it no longer describes anything.
        if (!stored) return { osv_id: id, status: "not-indexed", kind: null, severity: null, cvss: null };
        if (stored.withdrawn === 1) return { osv_id: id, status: "withdrawn", kind: null, severity: null, cvss: null };
        const advisory = readAdvisory(stored);
        return { osv_id: id, status: "current", kind: advisory.kind, severity: advisory.severity, cvss: advisory.cvss ?? null };
      }),
    }));
  } catch (err) {
    console.error("detection advisory metadata unavailable", err instanceof Error ? err.message : "unknown");
    return rows;
  }
}

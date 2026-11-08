import type { Ecosystem } from "../ecosystem-ids.js";
import { ECOSYSTEMS } from "../ecosystems/index.js";
import { normalizeName } from "../normalize.js";
import { distill } from "./distill.js";
import { buildKvEntry, type KvEntry } from "./index-entry.js";
import type { OsvRecord } from "./types.js";

export const OSV_QUERY_URL = "https://api.osv.dev/v1/query";

/** Request body for a package-wide (not version-specific) OSV query, so the answer can be cached per package. */
export function osvQueryBody(ecosystem: Ecosystem, name: string): { package: { ecosystem: string; name: string } } {
  return { package: { ecosystem: ECOSYSTEMS[ecosystem].osvName, name: normalizeName(ecosystem, name) } };
}

/** Keeps only well-formed records from an untrusted OSV API response. */
export function parseOsvResponse(body: unknown): { records: OsvRecord[]; complete: boolean } {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return { records: [], complete: false };
  const { vulns, next_page_token: next } = body as { vulns?: unknown; next_page_token?: unknown };
  const list = vulns === undefined ? [] : Array.isArray(vulns) ? vulns : null;
  if (list === null) return { records: [], complete: false };
  const records = list.filter(
    (r): r is OsvRecord => typeof r === "object" && r !== null && typeof r.id === "string" && typeof r.modified === "string",
  );
  return { records, complete: next === undefined && records.length === list.length };
}

/** Same shape as an index entry, built from live records. Null when nothing applies to this package. */
export function entryFromOsvRecords(
  ecosystem: Ecosystem,
  name: string,
  records: OsvRecord[],
  updated: string,
): KvEntry | null {
  const wanted = normalizeName(ecosystem, name);
  const rows = records.flatMap(distill).filter((a) => a.ecosystem === ecosystem && a.packageName === wanted);
  return buildKvEntry(rows, updated);
}

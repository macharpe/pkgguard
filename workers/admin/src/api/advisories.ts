import { evaluate, kvKey, normalizeName, parseKvValue, isNegative, summarizeVerdict, type Ecosystem } from "@pkgguard/core";
import type { Env } from "../env.js";
import { HttpError, enumParam, json } from "../http.js";

const ECOSYSTEMS = ["npm", "pypi"] as const satisfies readonly Ecosystem[];
const MAX_PACKAGES = 25;
const MAX_ROWS = 200;

interface Row {
  ecosystem: string;
  package_name: string;
  osv_id: string;
  kind: string;
  severity: string | null;
  summary: string | null;
}

/**
 * Package search by name prefix. With `version`, an exact package also gets the verdict the filter's OSV
 * index would give it. Overrides are not applied here, so the field is named `osv`, not `decision`.
 */
export async function advisories(env: Env, url: URL): Promise<Response> {
  const q = (url.searchParams.get("q") ?? "").trim();
  if (q === "") throw new HttpError(400, "q is required");
  if (q.length > 214) throw new HttpError(400, "q is too long");
  const only = enumParam(url, "ecosystem", ECOSYSTEMS);
  const version = (url.searchParams.get("version") ?? "").trim();
  if (version.length > 128) throw new HttpError(400, "version is too long");

  const packages = new Map<string, { ecosystem: string; name: string; malware: Row[]; vulnerabilities: Row[] }>();
  for (const ecosystem of only ? [only] : ECOSYSTEMS) {
    const prefix = normalizeName(ecosystem, q);
    const { results } = await env.DB.prepare(
      "SELECT ecosystem, package_name, osv_id, kind, severity, summary FROM advisories " +
        "WHERE ecosystem = ? AND withdrawn = 0 AND package_name >= ? AND package_name < ? ORDER BY package_name, osv_id LIMIT ?",
    )
      .bind(ecosystem, prefix, `${prefix}\uffff`, MAX_ROWS)
      .all<Row>();
    for (const row of results) {
      const key = `${row.ecosystem}:${row.package_name}`;
      if (!packages.has(key) && packages.size >= MAX_PACKAGES) continue;
      const entry = packages.get(key) ?? { ecosystem: row.ecosystem, name: row.package_name, malware: [], vulnerabilities: [] };
      (row.kind === "malware" ? entry.malware : entry.vulnerabilities).push(row);
      packages.set(key, entry);
    }
  }

  const items = await Promise.all(
    [...packages.values()].map(async (pkg) => {
      const exact = pkg.name === normalizeName(pkg.ecosystem as Ecosystem, q);
      if (version === "" || !exact) return pkg;
      const key = kvKey(pkg.ecosystem as Ecosystem, pkg.name);
      let value: ReturnType<typeof parseKvValue> = null;
      try {
        value = key ? parseKvValue(await env.PKG_INDEX.get(key, "json")) : null;
      } catch {
        // The filter fails open on an unreadable entry and records it as a lookup error; show the same.
        return { ...pkg, osv: { version, outcome: "error" as const, reason: "lookup-error" as const, osvIds: [] as string[] } };
      }
      const verdict = value && !isNegative(value) ? evaluate(pkg.ecosystem as Ecosystem, value, version) : { malware: [], vulnerabilities: [] };
      const summary = summarizeVerdict(verdict);
      return { ...pkg, osv: { version, outcome: summary.outcome, reason: summary.reason, osvIds: summary.osvIds } };
    }),
  );
  return json({ items, truncated: packages.size >= MAX_PACKAGES });
}

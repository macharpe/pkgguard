import { ECOSYSTEMS, distillFor, kvKey, normalizeName, type Ecosystem, type OsvRecord } from "../../packages/core/src/index.js";

/**
 * What an OSV feed would do to an ecosystem's handling, measured before any of it is loaded. Every question here is
 * one whose wrong answer is silent in production:
 *
 * - a range boundary the comparator cannot read makes the whole range never match, so that advisory flags nothing
 *   below it; a version in an explicit list that cannot be read still matches the identical string, so it is the
 *   lesser problem and is counted apart;
 * - two spellings that normalise to one name are merged, which is right only if the registry treats them as one;
 * - a name too long for a KV key is skipped, which the filter reads as "no match";
 * - a record that cannot be read at all stops an ingestion batch.
 *
 * It uses the same `distillFor` path the load and the refresh use, so it counts what they would store.
 */
export interface CensusReport {
  ecosystem: Ecosystem;
  records: number;
  /** Not JSON objects with an id and a modified time. */
  malformed: number;
  /** Well-formed, but distilling them threw: the kind of record that aborts a batch. */
  unreadable: number;
  packages: number;
  /** Distinct malware records, by the first route that catches each: its own id, an alias, or the CWE rule. */
  malware: { records: number; byPrefix: number; byAlias: number; byCwe: number };
  /** The `introduced`, `fixed` and `last_affected` of every range. An unreadable one makes its range inert. */
  boundaries: { total: number; rejected: number; rejectedInMalware: number; examples: string[] };
  /** The explicit `versions` lists. An unreadable one still matches the identical string. */
  listed: { total: number; rejected: number; examples: string[] };
  /** Normalised names that more than one raw spelling reaches. */
  merged: { names: number; examples: string[][] };
  oversizedKeys: number;
}

const EXAMPLES = 5;

export class Census {
  private records = 0;
  private malformed = 0;
  private unreadable = 0;
  private readonly spellings = new Map<string, Set<string>>();
  private readonly malwareIds = new Set<string>();
  private readonly prefixed = new Set<string>();
  private readonly aliased = new Set<string>();
  private readonly oversized = new Set<string>();
  private boundariesTotal = 0;
  private boundariesRejected = 0;
  private boundariesRejectedInMalware = 0;
  private readonly boundaryExamples = new Set<string>();
  private listedTotal = 0;
  private listedRejected = 0;
  private readonly listedExamples = new Set<string>();

  constructor(readonly ecosystem: Ecosystem) {}

  add(raw: unknown): void {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return void this.malformed++;
    const record = raw as OsvRecord;
    if (typeof record.id !== "string" || typeof record.modified !== "string") return void this.malformed++;
    this.records++;
    try {
      this.count(record);
    } catch {
      this.unreadable++;
    }
  }

  private count(record: OsvRecord): void {
    const spec = ECOSYSTEMS[this.ecosystem];
    const rows = distillFor(record, [this.ecosystem]);
    const inMalware = rows.some((row) => row.kind === "malware");
    for (const row of rows) {
      if (row.kind === "malware") {
        this.malwareIds.add(record.id);
        if (record.id.startsWith("MAL-")) this.prefixed.add(record.id);
        else if ((record.aliases ?? []).some((alias) => typeof alias === "string" && alias.startsWith("MAL-"))) this.aliased.add(record.id);
      }
      if (kvKey(this.ecosystem, row.packageName) === null) this.oversized.add(row.packageName);
    }

    for (const affected of record.affected ?? []) {
      if (affected.package?.ecosystem !== spec.osvName || typeof affected.package.name !== "string") continue;
      const normalised = normalizeName(this.ecosystem, affected.package.name);
      const seen = this.spellings.get(normalised);
      if (seen) seen.add(affected.package.name);
      else this.spellings.set(normalised, new Set([affected.package.name]));

      const unreadable = (version: unknown): version is string =>
        typeof version === "string" && version !== "" && version !== "0" && spec.compare(version, version) === null;
      // "0" is OSV's beginning of time, not a version; the matcher treats it specially.
      const countable = (version: unknown): version is string => typeof version === "string" && version !== "" && version !== "0";

      for (const version of affected.versions ?? []) {
        if (!countable(version)) continue;
        this.listedTotal++;
        if (unreadable(version)) {
          this.listedRejected++;
          if (this.listedExamples.size < EXAMPLES) this.listedExamples.add(version);
        }
      }
      for (const range of affected.ranges ?? []) {
        if (range.type === "GIT") continue;
        for (const event of range.events) {
          for (const version of [event.introduced, event.fixed, event.last_affected]) {
            if (!countable(version)) continue;
            this.boundariesTotal++;
            if (unreadable(version)) {
              this.boundariesRejected++;
              if (inMalware) this.boundariesRejectedInMalware++;
              if (this.boundaryExamples.size < EXAMPLES) this.boundaryExamples.add(version);
            }
          }
        }
      }
    }
  }

  report(): CensusReport {
    const merged = [...this.spellings.values()].filter((names) => names.size > 1);
    return {
      ecosystem: this.ecosystem,
      records: this.records,
      malformed: this.malformed,
      unreadable: this.unreadable,
      packages: this.spellings.size,
      malware: {
        records: this.malwareIds.size,
        byPrefix: this.prefixed.size,
        byAlias: this.aliased.size,
        byCwe: this.malwareIds.size - this.prefixed.size - this.aliased.size,
      },
      boundaries: { total: this.boundariesTotal, rejected: this.boundariesRejected, rejectedInMalware: this.boundariesRejectedInMalware, examples: [...this.boundaryExamples] },
      listed: { total: this.listedTotal, rejected: this.listedRejected, examples: [...this.listedExamples] },
      merged: { names: merged.length, examples: merged.slice(0, 3).map((names) => [...names].sort()) },
      oversizedKeys: this.oversized.size,
    };
  }
}

/** Anything a person has to look at before the ecosystem is loaded. Empty means the census is clean. */
export function findings(report: CensusReport): string[] {
  const out: string[] = [];
  const percent = (part: number, whole: number): string => (whole === 0 ? "0.0" : ((100 * part) / whole).toFixed(1));
  const b = report.boundaries;
  if (b.rejected > 0) {
    const malware = b.rejectedInMalware > 0 ? `, ${b.rejectedInMalware} of them in malware advisories` : ", none in malware advisories";
    out.push(`${b.rejected} of ${b.total} range boundaries (${percent(b.rejected, b.total)}%) cannot be read by the ${report.ecosystem} comparator${malware}, so those ranges never match: ${b.examples.join(", ")}`);
  }
  const l = report.listed;
  if (l.rejected > 0) {
    out.push(`${l.rejected} of ${l.total} listed versions (${percent(l.rejected, l.total)}%) cannot be read, so they match only the identical string and a differently written equal version would miss: ${l.examples.join(", ")}`);
  }
  if (report.unreadable > 0) out.push(`${report.unreadable} records could not be distilled and would abort an ingestion batch`);
  if (report.malformed > 0) out.push(`${report.malformed} records are not well-formed OSV (no id or modified time)`);
  if (report.oversizedKeys > 0) out.push(`${report.oversizedKeys} package names are too long for a KV key and would be skipped`);
  if (report.merged.names > 0) {
    out.push(`${report.merged.names} names are reached by more than one spelling and are merged (check the registry treats them as one package): ${report.merged.examples.map((names) => names.join(" = ")).join("; ")}`);
  }
  return out;
}

export function formatCensus(report: CensusReport): string {
  const lines = [
    `${report.ecosystem}`,
    `  records ${report.records}   packages ${report.packages}   malware ${report.malware.records} (${report.malware.byPrefix} by MAL- id, ${report.malware.byAlias} by a MAL- alias, ${report.malware.byCwe} by the CWE rule)`,
    `  range boundaries ${report.boundaries.total}, unreadable ${report.boundaries.rejected}   listed versions ${report.listed.total}, unreadable ${report.listed.rejected}`,
  ];
  const found = findings(report);
  if (found.length === 0) lines.push("  clean");
  else lines.push(...found.map((f) => `  REVIEW: ${f}`));
  return lines.join("\n");
}

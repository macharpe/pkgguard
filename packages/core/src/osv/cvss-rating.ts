/**
 * CVSS rating types and the stored-value reader. Deliberately free of the scoring library: the filter Worker imports
 * this package, and it must not carry a CVSS calculator it never uses. Scoring lives in `../cvss.ts`
 * (`@pkgguard/core/cvss`), for ingestion only.
 */

/** The CVSS versions whose base score is computed. v2 is not rated: OSV rarely carries it and it is retired. */
export const CVSS_VERSIONS = ["3.0", "3.1", "4.0"] as const;
export type CvssVersion = (typeof CVSS_VERSIONS)[number];

/** Where a rating came from. Strings, not an enum, so a stored value stays readable if a source is added later. */
export const CVSS_SOURCE_RECORD = "OSV severity";
export const CVSS_SOURCE_AFFECTED = "OSV affected severity";

export interface CvssRating {
  /** Base score, 0.0 to 10.0, computed by the scoring library from `vector` (never taken from the feed). */
  score: number;
  /** "3.0", "3.1" or "4.0". */
  version: string;
  /** The vector exactly as OSV published it. */
  vector: string;
  /** Provenance: which OSV field it came from. */
  source: string;
}

/** An unvalidated `severity[]` entry from an OSV record, tagged with where it was found. */
export interface CvssCandidate {
  type: string;
  score: string;
  source: string;
}

/** FIRST's qualitative scale, lowercase. Not the same vocabulary as the categorical `severity` column. */
export type CvssLabel = "none" | "low" | "medium" | "high" | "critical";

/** 0.0 none; 0.1-3.9 low; 4.0-6.9 medium; 7.0-8.9 high; 9.0-10.0 critical. Null for anything that is not a score. */
export function cvssLabel(score: number): CvssLabel | null {
  if (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 10) return null;
  if (score === 0) return "none";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}

export const VECTOR_MAX = 512;
export const SOURCE_MAX = 64;

const isVersion = (value: unknown): value is CvssVersion => CVSS_VERSIONS.includes(value as CvssVersion);

/** The version a vector declares, or null when it has no supported `CVSS:x.y/` prefix. */
export function cvssVectorVersion(vector: string): CvssVersion | null {
  const match = /^CVSS:(\d\.\d)\//.exec(vector);
  return match && isVersion(match[1]) ? match[1] : null;
}

/**
 * Reads a stored rating: the parsed object or the `cvss_json` column text. Returns null for anything that is not
 * exactly a rating (wrong shape, score outside 0-10, unsupported version, a vector whose prefix disagrees with
 * `version`, an over-long string). Extra properties are dropped. It does not re-score the vector: the writer did.
 */
export function parseCvssRating(value: unknown): CvssRating | null {
  let raw = value;
  if (typeof raw === "string") {
    try {
      raw = JSON.parse(raw);
    } catch {
      return null;
    }
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const { score, version, vector, source } = raw as Record<string, unknown>;
  if (typeof score !== "number" || cvssLabel(score) === null) return null;
  if (!isVersion(version)) return null;
  if (typeof vector !== "string" || vector.length === 0 || vector.length > VECTOR_MAX) return null;
  if (cvssVectorVersion(vector) !== version) return null;
  if (typeof source !== "string" || source.length === 0 || source.length > SOURCE_MAX) return null;
  return { score, version, vector, source };
}

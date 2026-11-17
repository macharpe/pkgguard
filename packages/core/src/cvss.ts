/**
 * Scoring CVSS vectors from OSV records. Ingestion only: it runs when an advisory is written (bootstrap, refresh), never
 * on the filter's hot path, and it is not re-exported from the package index so the filter Worker does not bundle the
 * scoring library. Import it as `@pkgguard/core/cvss`.
 *
 * The arithmetic is `ae-cvss-calculator`'s (CVSS 3.0, 3.1 and 4.0 as published by FIRST). This module adds the strictness
 * the library lacks: it silently accepts duplicate metrics (`AV:N/AV:L` scores as `AV:L`), spelled-out values
 * (`AV:Network`) and a 3.0 vector inside a 3.1 parser, and it scores an unknown or partial vector as 0 or not at all.
 * A vector that is not exactly well formed is refused, never repaired.
 */
import { Cvss3P0, Cvss3P1, Cvss4P0, type CvssVector } from "ae-cvss-calculator";
import {
  CVSS_SOURCE_AFFECTED,
  CVSS_SOURCE_RECORD,
  VECTOR_MAX,
  cvssVectorVersion,
  type CvssCandidate,
  type CvssRating,
  type CvssVersion,
} from "./osv/cvss-rating.js";
import { ENABLED_ECOSYSTEMS, type Ecosystem } from "./ecosystem-ids.js";
import { ecosystemFromOsvName } from "./ecosystems/index.js";
import { normalizeName } from "./normalize.js";
import { distillFor, type Advisory } from "./osv/distill.js";
import type { OsvRecord, OsvSeverity } from "./osv/types.js";

export * from "./osv/cvss-rating.js";

type AnyVector = CvssVector<{ vector: string; overall: number; normalized: boolean }>;

const CREATE: Record<CvssVersion, (vector?: string) => AnyVector> = {
  "3.0": (v) => new Cvss3P0(v) as unknown as AnyVector,
  "3.1": (v) => new Cvss3P1(v) as unknown as AnyVector,
  "4.0": (v) => new Cvss4P0(v) as unknown as AnyVector,
};

/** OSV's `severity[].type` that carries each version. A vector under the wrong type is refused. */
const TYPE_VERSIONS: Record<string, readonly CvssVersion[]> = {
  CVSS_V3: ["3.0", "3.1"],
  CVSS_V4: ["4.0"],
};

const PART = /^([A-Za-z]{1,4}):([A-Za-z0-9]{1,8})$/;

function baseKeys(version: CvssVersion): Set<string> {
  const keys = new Set<string>();
  for (const [category, components] of CREATE[version]().getRegisteredComponents()) {
    if (category.name === "base") for (const c of components) keys.add(c.shortName);
  }
  return keys;
}

function allKeys(version: CvssVersion): Set<string> {
  const keys = new Set<string>();
  for (const components of CREATE[version]().getRegisteredComponents().values()) for (const c of components) keys.add(c.shortName);
  return keys;
}

const BASE = new Map<CvssVersion, Set<string>>();
const ALL = new Map<CvssVersion, Set<string>>();
const baseOf = (v: CvssVersion): Set<string> => BASE.get(v) ?? (BASE.set(v, baseKeys(v)), BASE.get(v)!);
const allOf = (v: CvssVersion): Set<string> => ALL.get(v) ?? (ALL.set(v, allKeys(v)), ALL.get(v)!);

/**
 * The base score of a vector, or null when the vector is not well formed. Well formed means: a supported `CVSS:x.y/`
 * prefix; every other part is `KEY:VALUE` with a metric of that version and a value the library knows by its short
 * name; no metric twice; and every base metric present and defined (`X` is not accepted for a base metric).
 * Temporal, threat and environmental metrics are allowed and ignored: the score is the base score, so a vector's
 * rating does not move with how a consumer has tuned it.
 */
export function scoreCvssVector(vector: unknown): { score: number; version: CvssVersion } | null {
  if (typeof vector !== "string" || vector.length === 0 || vector.length > VECTOR_MAX) return null;
  const version = cvssVectorVersion(vector);
  if (version === null) return null;
  const parts = vector.split("/").slice(1);
  const seen = new Map<string, string>();
  for (const part of parts) {
    const match = PART.exec(part);
    if (!match) return null;
    const [, key, value] = match as unknown as [string, string, string];
    if (seen.has(key) || !allOf(version).has(key)) return null;
    seen.set(key, value);
  }
  const base = baseOf(version);
  for (const key of base) if (!seen.has(key)) return null;
  try {
    // Every metric the vector carries must hold a value the library knows (it throws on one it does not), including the
    // temporal and environmental ones the score ignores: a vector with a bad `E:Q` is malformed, not partly usable.
    const full = CREATE[version](vector);
    for (const [key, value] of seen) if (full.getComponentByStringOpt(key)?.shortName !== value) return null;
    // Scored from the base metrics alone, so threat or environmental metrics never change the rating.
    const scorer = CREATE[version](`CVSS:${version}/${[...base].map((k) => `${k}:${seen.get(k)}`).join("/")}`);
    // The library also accepts a metric's long name; only the short name is OSV's vocabulary.
    for (const key of base) if (scorer.getComponentByStringOpt(key)?.shortName !== seen.get(key)) return null;
    if (!scorer.isBaseFullyDefined()) return null;
    const scores = scorer.calculateScores() as unknown as { base?: number; overall: number };
    const score = typeof scores.base === "number" ? scores.base : NaN;
    if (!Number.isFinite(score) || score < 0 || score > 10) return null;
    return { score, version };
  } catch {
    return null;
  }
}

/** Scores one candidate. Null for an unsupported type (including CVSS_V2), a type/version mismatch, or a bad vector. */
export function rateCandidate(candidate: CvssCandidate): CvssRating | null {
  if (typeof candidate.type !== "string" || typeof candidate.score !== "string") return null;
  const allowed = Object.hasOwn(TYPE_VERSIONS, candidate.type) ? TYPE_VERSIONS[candidate.type] : undefined;
  if (!allowed) return null;
  const scored = scoreCvssVector(candidate.score);
  if (!scored || !allowed.includes(scored.version)) return null;
  return { score: scored.score, version: scored.version, vector: candidate.score, source: candidate.source };
}

/**
 * The deterministic choice among ratings: highest base score; then the newest CVSS version; then the vector text,
 * ascending; then the source, ascending. Null for an empty list.
 */
export function chooseCvssRating(ratings: readonly CvssRating[]): CvssRating | null {
  let best: CvssRating | null = null;
  for (const r of ratings) {
    if (best === null || compare(r, best) < 0) best = r;
  }
  return best;
}

function compare(a: CvssRating, b: CvssRating): number {
  if (a.score !== b.score) return b.score - a.score;
  if (a.version !== b.version) return a.version < b.version ? 1 : -1;
  if (a.vector !== b.vector) return a.vector < b.vector ? -1 : 1;
  return a.source < b.source ? -1 : a.source > b.source ? 1 : 0;
}

const candidates = (list: OsvSeverity[] | undefined, source: string): CvssCandidate[] =>
  Array.isArray(list)
    ? list.flatMap((s) => (s && typeof s.type === "string" && typeof s.score === "string" ? [{ type: s.type, score: s.score, source }] : []))
    : [];

/** Every rating in a record's own top-level `severity`, invalid entries dropped. */
export function recordRatings(record: OsvRecord): CvssRating[] {
  return candidates(record.severity, CVSS_SOURCE_RECORD).flatMap((c) => rateCandidate(c) ?? []);
}

/** Ratings from the record's top level plus those on the `affected[]` entries naming this package, by the caller's test. */
export function ratingFor(record: OsvRecord, affectedMatches: (affected: NonNullable<OsvRecord["affected"]>[number]) => boolean): CvssRating | null {
  const ratings = recordRatings(record);
  for (const affected of record.affected ?? []) {
    if (affected && affectedMatches(affected)) {
      for (const c of candidates(affected.severity, CVSS_SOURCE_AFFECTED)) {
        const rated = rateCandidate(c);
        if (rated) ratings.push(rated);
      }
    }
  }
  return chooseCvssRating(ratings);
}

/**
 * `distillFor`, plus a rating on each vulnerability row: the best rating among the record's top-level `severity` and the
 * `severity` of the `affected[]` entries that name that row's own package, so a rating on one package never lands on
 * another. A malware row never gets a rating (the feed's score for a malicious package describes nothing real), and
 * neither does a row with no valid vector. `severity` (the categorical fallback) and every other field are untouched.
 */
export function distillRatedFor(record: OsvRecord, ecosystems: readonly Ecosystem[]): Advisory[] {
  const rows = distillFor(record, ecosystems);
  return rows.map((row) => {
    if (row.kind === "malware") return row;
    try {
      const rating = ratingFor(record, (affected) => {
        const eco = ecosystemFromOsvName(affected.package?.ecosystem, [row.ecosystem]);
        const name = affected.package?.name;
        return eco === row.ecosystem && typeof name === "string" && name.trim() !== "" && normalizeName(eco, name) === row.packageName;
      });
      return rating ? { ...row, cvss: rating } : row;
    } catch {
      // Scores are display-only. A scorer failure must never prevent an advisory or malware update being ingested.
      return row;
    }
  });
}

/** `distill`, with ratings, for the enabled ecosystems. One argument, so it is safe to pass to `flatMap`. */
export function distillRated(record: OsvRecord): Advisory[] {
  return distillRatedFor(record, ENABLED_ECOSYSTEMS);
}

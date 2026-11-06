import {
  entryFromOsvRecords,
  evaluate,
  isNegative,
  kvKey,
  normalizeName,
  overrideApplies,
  overrideKey,
  parseKvValue,
  parseOverride,
  summarizeVerdict,
  type KvValue,
  type ParsedPackage,
  type Verdict,
} from "@pkgguard/core";
import { queryOsv, type FetchLike } from "./osv-client.js";

export type DetectionVerdict = "blocked" | "flagged" | "allowed" | "error";
export type DetectionReason = "osv-malware" | "osv-cve" | "override" | "lookup-error";
export type DetectionSource = "index" | "live-osv" | "override";

export interface Decision {
  /** True when policy says to stop the download. Whether that happens depends on ENFORCE. */
  block: boolean;
  verdict: DetectionVerdict;
  reason: DetectionReason | null;
  osvIds: string[];
  source: DetectionSource;
  /** A live lookup result worth keeping, so the next request for this package skips OSV. */
  cache?: { key: string; value: KvValue };
}

export interface DecideDeps {
  kv: Pick<KVNamespace, "get">;
  fetch: FetchLike;
  osvTimeoutMs: number;
  now: () => string;
}

const allowed = (source: DetectionSource): Decision => ({
  block: false,
  verdict: "allowed",
  reason: null,
  osvIds: [],
  source,
});

function fromVerdict(verdict: Verdict, source: DetectionSource): Decision {
  const summary = summarizeVerdict(verdict);
  if (summary.outcome === "allowed") return allowed(source);
  return { block: summary.outcome === "blocked", verdict: summary.outcome, reason: summary.reason, osvIds: summary.osvIds, source };
}

export const fullName = (pkg: ParsedPackage): string => (pkg.namespace ? `${pkg.namespace}/${pkg.name}` : pkg.name);

/**
 * Override lists, then the KV index, then (on a miss) a live OSV lookup.
 * Allow beats block, and both beat OSV. Throws only on a KV failure; the caller fails open.
 */
export async function decide(pkg: ParsedPackage, deps: DecideDeps): Promise<Decision> {
  const name = fullName(pkg);
  const key = kvKey(pkg.ecosystem, name);
  if (key === null) return allowed("index");

  const allowKey = overrideKey("allow", pkg.ecosystem, name);
  const blockKey = overrideKey("block", pkg.ecosystem, name);
  const [allowRaw, blockRaw, indexRaw] = await Promise.all([
    allowKey ? deps.kv.get(allowKey, "json") : null,
    blockKey ? deps.kv.get(blockKey, "json") : null,
    deps.kv.get(key, "json"),
  ]);

  const allow = parseOverride(allowRaw);
  if (allow && overrideApplies(pkg.ecosystem, allow, pkg.version)) {
    return { ...allowed("override"), reason: "override" };
  }
  const block = parseOverride(blockRaw);
  if (block && overrideApplies(pkg.ecosystem, block, pkg.version)) {
    return { block: true, verdict: "blocked", reason: "override", osvIds: [], source: "override" };
  }

  if (indexRaw !== null) {
    const value = parseKvValue(indexRaw);
    if (value !== null) {
      if (isNegative(value)) return allowed("live-osv");
      return fromVerdict(evaluate(pkg.ecosystem, value, pkg.version), "index");
    }
    console.error(JSON.stringify({ msg: "corrupt KV value, falling back to live lookup", key }));
  }

  if (deps.osvTimeoutMs <= 0) return allowed("index");
  return liveLookup(pkg, name, key, deps);
}

async function liveLookup(pkg: ParsedPackage, name: string, key: string, deps: DecideDeps): Promise<Decision> {
  let result;
  try {
    result = await queryOsv(deps.fetch, pkg.ecosystem, name, deps.osvTimeoutMs);
  } catch (err) {
    console.warn(JSON.stringify({ msg: "live OSV lookup failed", key, error: String(err) }));
    return { block: false, verdict: "error", reason: "lookup-error", osvIds: [], source: "live-osv" };
  }

  const updated = deps.now();
  const entry = entryFromOsvRecords(pkg.ecosystem, normalizeName(pkg.ecosystem, name), result.records, updated);
  const decision = entry ? fromVerdict(evaluate(pkg.ecosystem, entry, pkg.version), "live-osv") : allowed("live-osv");
  // An incomplete answer (pagination, malformed records) must not be remembered as authoritative.
  if (result.complete) decision.cache = { key, value: entry ?? { v: 1, n: true, u: updated } };
  return decision;
}

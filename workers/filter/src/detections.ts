import { normalizeName, toPurl, type ParsedPackage } from "@pkgguard/core";
import type { Decision, DetectionVerdict } from "./decide.js";
import { fullName } from "./decide.js";

export interface DetectionContext {
  email: string | null;
  srcIp: string | null;
}

const INSERT =
  "INSERT INTO detections (ts, ecosystem, package_name, version, purl, verdict, reason, osv_ids, user_email, src_ip, source, reference) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

export async function recordDetection(
  db: Pick<D1Database, "prepare">,
  pkg: ParsedPackage,
  decision: Decision,
  verdict: DetectionVerdict,
  who: DetectionContext,
  now: string,
  reference: string | null = null,
): Promise<void> {
  await db
    .prepare(INSERT)
    .bind(
      now,
      pkg.ecosystem,
      // The name as the index keys it. Lowercasing here would merge two Go modules that differ only by case.
      normalizeName(pkg.ecosystem, fullName(pkg)),
      pkg.version,
      toPurl(pkg),
      verdict,
      decision.reason,
      decision.osvIds.length > 0 ? decision.osvIds.join(",") : null,
      who.email,
      who.srcIp,
      decision.source,
      reference,
    )
    .run();
}

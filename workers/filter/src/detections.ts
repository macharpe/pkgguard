import { toPurl, type ParsedPackage } from "@pkgguard/core";
import type { Decision, DetectionVerdict } from "./decide.js";
import { fullName } from "./decide.js";

export interface DetectionContext {
  email: string | null;
  srcIp: string | null;
}

const INSERT =
  "INSERT INTO detections (ts, ecosystem, package_name, version, purl, verdict, reason, osv_ids, user_email, src_ip, source) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

export async function recordDetection(
  db: Pick<D1Database, "prepare">,
  pkg: ParsedPackage,
  decision: Decision,
  verdict: DetectionVerdict,
  who: DetectionContext,
  now: string,
): Promise<void> {
  await db
    .prepare(INSERT)
    .bind(
      now,
      pkg.ecosystem,
      fullName(pkg).toLowerCase(),
      pkg.version,
      toPurl(pkg),
      verdict,
      decision.reason,
      decision.osvIds.length > 0 ? decision.osvIds.join(",") : null,
      who.email,
      who.srcIp,
      decision.source,
    )
    .run();
}

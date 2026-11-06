import { isReference } from "@pkgguard/core";
import type { DetectionRow, DetectionsResponse } from "../api-types.js";
import type { Env } from "../env.js";
import { HttpError, enumParam, intParam, json } from "../http.js";

const VERDICTS = ["blocked", "flagged", "allowed", "error"] as const;
const ECOSYSTEMS = ["npm", "pypi"] as const;

/** A developer may type it in any case and with stray spaces; anything that is not a reference is a mistake. */
function referenceParam(url: URL): string | null {
  const raw = url.searchParams.get("reference")?.trim().toUpperCase();
  if (raw === undefined || raw === "") return null;
  if (!isReference(raw)) throw new HttpError(400, "reference must look like PG-7Q2K4M");
  return raw;
}

/** Newest first, keyset-paginated on id: `before` is the smallest id of the previous page. */
export async function detections(env: Env, url: URL): Promise<Response> {
  const verdict = enumParam(url, "verdict", VERDICTS);
  const ecosystem = enumParam(url, "ecosystem", ECOSYSTEMS);
  const reference = referenceParam(url);
  const limit = intParam(url, "limit", 50, 200);
  const beforeRaw = url.searchParams.get("before");
  const before = beforeRaw === null || beforeRaw === "" ? null : intParam(url, "before", 0, Number.MAX_SAFE_INTEGER);

  const where: string[] = [];
  const binds: Array<string | number> = [];
  if (verdict) (where.push("verdict = ?"), binds.push(verdict));
  if (ecosystem) (where.push("ecosystem = ?"), binds.push(ecosystem));
  if (reference) (where.push("reference = ?"), binds.push(reference));
  if (before !== null) (where.push("id < ?"), binds.push(before));

  const sql =
    "SELECT id, ts, ecosystem, package_name, version, purl, verdict, reason, osv_ids, user_email, src_ip, source, reference FROM detections" +
    (where.length > 0 ? ` WHERE ${where.join(" AND ")}` : "") +
    " ORDER BY id DESC LIMIT ?";
  const { results } = await env.DB.prepare(sql)
    .bind(...binds, limit + 1)
    .all<DetectionRow>();

  const more = results.length > limit;
  const items = more ? results.slice(0, limit) : results;
  const body: DetectionsResponse = { items, nextBefore: more ? (items[items.length - 1]?.id ?? null) : null };
  return json(body);
}

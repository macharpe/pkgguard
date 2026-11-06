export interface Env {
  PKG_INDEX: KVNamespace;
  DB: D1Database;
  OSV_API_TIMEOUT_MS: string;
  NEGATIVE_CACHE_TTL_S: string;
  /** Only the exact string "true" blocks. Anything else is observe-only. */
  ENFORCE: string;
  /** Where a blocked developer is told to ask for help. Plain text; falls back to a generic line. */
  SUPPORT_CONTACT?: string | undefined;
  /** Secret. A Google Chat incoming-webhook URL; alerts are skipped when it is absent. */
  GCHAT_WEBHOOK?: string | undefined;
}

export interface Settings {
  enforce: boolean;
  /** Zero disables the live OSV lookup. */
  osvTimeoutMs: number;
  cacheTtlSeconds: number;
}

const KV_MIN_TTL_SECONDS = 60;

function int(raw: string | undefined, fallback: number): number {
  const n = Number.parseInt(raw ?? "", 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export function readSettings(env: Pick<Env, "OSV_API_TIMEOUT_MS" | "NEGATIVE_CACHE_TTL_S" | "ENFORCE">): Settings {
  return {
    enforce: env.ENFORCE === "true",
    osvTimeoutMs: int(env.OSV_API_TIMEOUT_MS, 400),
    cacheTtlSeconds: Math.max(KV_MIN_TTL_SECONDS, int(env.NEGATIVE_CACHE_TTL_S, 3600)),
  };
}

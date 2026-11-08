import { isEcosystem, type Ecosystem } from "@pkgguard/core";

export interface Env {
  PKG_INDEX: KVNamespace;
  DB: D1Database;
  OSV_API_TIMEOUT_MS: string;
  NEGATIVE_CACHE_TTL_S: string;
  /** Only the exact string "true" blocks. Anything else is observe-only. */
  ENFORCE: string;
  /**
   * Comma-separated ecosystem ids that never block, whatever ENFORCE says: a would-be block is recorded as flagged.
   * A new ecosystem starts here, so its traffic can be watched before it can stop anyone.
   */
  OBSERVE_ONLY?: string | undefined;
  /** Where a blocked developer is told to ask for help. Plain text; falls back to a generic line. */
  SUPPORT_CONTACT?: string | undefined;
  /** Secret. A Google Chat incoming-webhook URL; alerts are skipped when it is absent. */
  GCHAT_WEBHOOK?: string | undefined;
}

export interface Settings {
  enforce: boolean;
  observeOnly: ReadonlySet<Ecosystem>;
  /** Zero disables the live OSV lookup. */
  osvTimeoutMs: number;
  cacheTtlSeconds: number;
}

const KV_MIN_TTL_SECONDS = 60;

function int(raw: string | undefined, fallback: number): number {
  const n = Number.parseInt(raw ?? "", 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

/** Unknown ids are ignored here; the deploy generator refuses them, so a typo is caught before it ships. */
function ecosystems(raw: string | undefined): ReadonlySet<Ecosystem> {
  return new Set((raw ?? "").split(",").map((part) => part.trim()).filter(isEcosystem));
}

/** Whether a package of this ecosystem may actually be stopped. */
export const enforces = (settings: Pick<Settings, "enforce" | "observeOnly">, ecosystem: Ecosystem): boolean =>
  settings.enforce && !settings.observeOnly.has(ecosystem);

export function readSettings(env: Pick<Env, "OSV_API_TIMEOUT_MS" | "NEGATIVE_CACHE_TTL_S" | "ENFORCE" | "OBSERVE_ONLY">): Settings {
  return {
    enforce: env.ENFORCE === "true",
    observeOnly: ecosystems(env.OBSERVE_ONLY),
    osvTimeoutMs: int(env.OSV_API_TIMEOUT_MS, 400),
    cacheTtlSeconds: Math.max(KV_MIN_TTL_SECONDS, int(env.NEGATIVE_CACHE_TTL_S, 3600)),
  };
}

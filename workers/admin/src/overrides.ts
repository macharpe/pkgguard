import { ECOSYSTEMS, ENABLED_ECOSYSTEMS, normalizeName, overrideKey, type Ecosystem, type KvOverride, type OverrideMode } from "@pkgguard/core";
import type { Env } from "./env.js";
import { HttpError } from "./http.js";

export interface OverrideInput {
  ecosystem: Ecosystem;
  name: string;
  mode: OverrideMode;
  versions: string[] | null;
  note: string | null;
}

export interface OverrideRow {
  ecosystem: Ecosystem;
  package_name: string;
  mode: OverrideMode;
  versions: string[] | null;
  note: string | null;
  created_by: string;
  created_at: string;
}

export const MAX_OVERRIDES = 1000;
const MAX_VERSIONS = 100;
const VERSION = /^[A-Za-z0-9._+!~-]{1,128}$/;
const NOTE_MAX = 500;

const MODES = ["block", "allow"] as const;

function pick<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) throw new HttpError(400, `${field} must be one of ${allowed.join(", ")}`);
  return value as T;
}

function parseName(ecosystem: Ecosystem, value: unknown): string {
  if (typeof value !== "string") throw new HttpError(400, "name is required");
  const raw = value.trim();
  const spec = ECOSYSTEMS[ecosystem];
  if (raw === "" || raw.length > spec.maxNameLength) throw new HttpError(400, `name must be 1 to ${spec.maxNameLength} characters`);
  const name = normalizeName(ecosystem, raw);
  if (!spec.overrideNamePattern.test(name)) throw new HttpError(400, "name contains characters a package name cannot have");
  if (overrideKey("block", ecosystem, name) === null) throw new HttpError(400, "name is too long");
  return name;
}

/** Validates everything an administrator sends, and normalises the name the same way the filter will. */
export function parseOverrideInput(body: Record<string, unknown>): OverrideInput {
  const ecosystem = pick(body["ecosystem"], ENABLED_ECOSYSTEMS, "ecosystem");
  const mode = pick(body["mode"], MODES, "mode");
  const name = parseName(ecosystem, body["name"]);

  const rawVersions = body["versions"];
  let versions: string[] | null = null;
  if (rawVersions !== undefined && rawVersions !== null) {
    if (!Array.isArray(rawVersions)) throw new HttpError(400, "versions must be a list, or omitted for all versions");
    if (rawVersions.length === 0) throw new HttpError(400, "versions must not be empty: omit it to cover every version");
    if (rawVersions.length > MAX_VERSIONS) throw new HttpError(400, `at most ${MAX_VERSIONS} versions`);
    const cleaned = rawVersions.map((v) => (typeof v === "string" ? v.trim() : ""));
    if (cleaned.some((v) => !VERSION.test(v))) throw new HttpError(400, "a version contains characters a version cannot have");
    versions = [...new Set(cleaned)];
  }

  let note: string | null = null;
  if (body["note"] !== undefined && body["note"] !== null) {
    if (typeof body["note"] !== "string") throw new HttpError(400, "note must be text");
    const text = body["note"].replace(/[\u0000-\u001f]/g, " ").trim();
    if (text.length > NOTE_MAX) throw new HttpError(400, `note must be at most ${NOTE_MAX} characters`);
    note = text === "" ? null : text;
  }
  return { ecosystem, name, mode, versions, note };
}

export function parseOverrideRef(body: Record<string, unknown>): Pick<OverrideInput, "ecosystem" | "name" | "mode"> {
  const ecosystem = pick(body["ecosystem"], ENABLED_ECOSYSTEMS, "ecosystem");
  return { ecosystem, mode: pick(body["mode"], MODES, "mode"), name: parseName(ecosystem, body["name"]) };
}

const kvValue = (input: Pick<OverrideInput, "versions" | "note">): KvOverride => ({
  v: 1,
  versions: input.versions,
  ...(input.note ? { note: input.note } : {}),
});

interface Stored {
  ecosystem: Ecosystem;
  package_name: string;
  mode: OverrideMode;
  version_spec: string | null;
  note: string | null;
  created_by: string;
  created_at: string;
}

const toRow = (s: Stored): OverrideRow => {
  let versions: string[] | null = null;
  if (s.version_spec !== null) {
    try {
      const parsed: unknown = JSON.parse(s.version_spec);
      if (Array.isArray(parsed) && parsed.every((v) => typeof v === "string")) versions = parsed;
    } catch {
      /* an unreadable spec is shown as covering all versions only if the KV value agrees; the UI shows what is stored */
    }
  }
  return { ecosystem: s.ecosystem, package_name: s.package_name, mode: s.mode, versions, note: s.note, created_by: s.created_by, created_at: s.created_at };
};

const SELECT = "SELECT ecosystem, package_name, mode, version_spec, note, created_by, created_at FROM overrides";

export async function listOverrides(db: D1Database): Promise<OverrideRow[]> {
  const { results } = await db.prepare(`${SELECT} ORDER BY created_at DESC, package_name`).all<Stored>();
  return results.map(toRow);
}

const find = (db: D1Database, ref: Pick<OverrideInput, "ecosystem" | "name" | "mode">): Promise<Stored | null> =>
  db.prepare(`${SELECT} WHERE ecosystem = ? AND package_name = ? AND mode = ?`).bind(ref.ecosystem, ref.name, ref.mode).first<Stored>();

const restore = (db: D1Database, previous: Stored | null, ref: Pick<OverrideInput, "ecosystem" | "name" | "mode">): Promise<unknown> =>
  previous === null
    ? db.prepare("DELETE FROM overrides WHERE ecosystem = ? AND package_name = ? AND mode = ?").bind(ref.ecosystem, ref.name, ref.mode).run()
    : db
        .prepare("INSERT OR REPLACE INTO overrides (ecosystem, package_name, mode, version_spec, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(previous.ecosystem, previous.package_name, previous.mode, previous.version_spec, previous.note, previous.created_by, previous.created_at)
        .run();

/**
 * D1 is written first, then the KV mirror the filter actually reads. If the KV write fails the D1 change is undone,
 * so the dashboard never shows an override the filter does not have.
 */
export async function putOverride(env: Pick<Env, "DB" | "PKG_INDEX">, input: OverrideInput, actor: string, now: Date): Promise<{ created: boolean; row: OverrideRow }> {
  const previous = await find(env.DB, input);
  if (previous === null) {
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM overrides").first<{ n: number }>();
    if ((count?.n ?? 0) >= MAX_OVERRIDES) throw new HttpError(409, `the limit of ${MAX_OVERRIDES} overrides has been reached`);
  }
  const key = overrideKey(input.mode, input.ecosystem, input.name) as string;
  const createdAt = now.toISOString();

  await env.DB
    .prepare("INSERT OR REPLACE INTO overrides (ecosystem, package_name, mode, version_spec, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(input.ecosystem, input.name, input.mode, input.versions === null ? null : JSON.stringify(input.versions), input.note, actor, createdAt)
    .run();
  try {
    await env.PKG_INDEX.put(key, JSON.stringify(kvValue(input)));
  } catch (err) {
    await restore(env.DB, previous, input).catch(() => undefined);
    throw err;
  }
  return { created: previous === null, row: { ecosystem: input.ecosystem, package_name: input.name, mode: input.mode, versions: input.versions, note: input.note, created_by: actor, created_at: createdAt } };
}

/** Returns the removed override, or null when there was none. */
export async function deleteOverride(env: Pick<Env, "DB" | "PKG_INDEX">, ref: Pick<OverrideInput, "ecosystem" | "name" | "mode">): Promise<OverrideRow | null> {
  const previous = await find(env.DB, ref);
  const key = overrideKey(ref.mode, ref.ecosystem, ref.name) as string;
  if (previous === null) {
    // Nothing recorded, but make sure no stray KV copy keeps enforcing something the dashboard does not show.
    await env.PKG_INDEX.delete(key);
    return null;
  }
  await env.DB.prepare("DELETE FROM overrides WHERE ecosystem = ? AND package_name = ? AND mode = ?").bind(ref.ecosystem, ref.name, ref.mode).run();
  try {
    await env.PKG_INDEX.delete(key);
  } catch (err) {
    await restore(env.DB, previous, ref).catch(() => undefined);
    throw err;
  }
  return toRow(previous);
}

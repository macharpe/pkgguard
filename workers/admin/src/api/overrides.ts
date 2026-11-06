import { overrideMessage } from "@pkgguard/core";
import { actorLabel, type Actor } from "../access-jwt.js";
import { audit } from "../audit.js";
import { postChat } from "../chat.js";
import type { Env } from "../env.js";
import { HttpError, json, readJsonBody } from "../http.js";
import { deleteOverride, listOverrides, parseOverrideInput, parseOverrideRef, putOverride, type OverrideRow } from "../overrides.js";

export interface OverridesContext {
  env: Env;
  actor: Actor;
  now: Date;
  waitUntil: (work: Promise<unknown>) => void;
}

export async function overridesList(env: Env): Promise<Response> {
  return json({ items: await listOverrides(env.DB) });
}

export async function overridesAdd(request: Request, c: OverridesContext): Promise<Response> {
  const input = parseOverrideInput(await readJsonBody(request));
  const actor = actorLabel(c.actor);
  const { created, row } = await putOverride(c.env, input, actor, c.now);
  await audit(c.env.DB, c.now, actor, created ? "override.add" : "override.replace", `${row.mode}:${row.ecosystem}:${row.package_name}`);
  c.waitUntil(postChat(c.env, overrideMessage({ action: "added", mode: row.mode, ecosystem: row.ecosystem, name: row.package_name, versions: row.versions, note: row.note, actor })));
  return json({ created, item: row satisfies OverrideRow }, created ? 201 : 200);
}

export async function overridesRemove(request: Request, c: OverridesContext): Promise<Response> {
  const ref = parseOverrideRef(await readJsonBody(request));
  const actor = actorLabel(c.actor);
  const removed = await deleteOverride(c.env, ref);
  if (removed === null) throw new HttpError(404, "no such override");
  await audit(c.env.DB, c.now, actor, "override.remove", `${removed.mode}:${removed.ecosystem}:${removed.package_name}`);
  c.waitUntil(postChat(c.env, overrideMessage({ action: "removed", mode: removed.mode, ecosystem: removed.ecosystem, name: removed.package_name, versions: removed.versions, note: removed.note, actor })));
  return json({ removed });
}

/**
 * Writes workers/<name>/wrangler.local.jsonc from the committed wrangler.jsonc template.
 *   tsx scripts/generate-deploy-config.ts <filter|admin>
 */
import { chmodSync, existsSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadDeployEnv } from "./lib/deploy-env.js";
import { FIELD_NAMES, WORKERS, field, renderConfig, type FieldName } from "./lib/deploy-config.js";

export function generate(worker: string, root = process.cwd(), envFile = join(root, ".deploy.env")): string {
  const expected = WORKERS[worker];
  if (!expected) throw new Error(`Unknown worker "${worker}". Known: ${Object.keys(WORKERS).join(", ")}`);

  const dir = resolve(root, "workers", worker);
  const templatePath = join(dir, "wrangler.jsonc");
  if (!existsSync(templatePath)) throw new Error(`${templatePath} not found`);

  const needed = (Object.keys(expected) as FieldName[]).map((name) => field(name).env);
  const env = loadDeployEnv(needed, envFile);
  const values: Partial<Record<FieldName, string>> = {};
  for (const name of FIELD_NAMES) {
    const value = env[field(name).env];
    if (value !== undefined) values[name] = value;
  }

  const rendered = renderConfig(readFileSync(templatePath, "utf8"), expected, values);

  const target = join(dir, "wrangler.local.jsonc");
  const tmp = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(tmp, rendered, { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, target);
  } finally {
    rmSync(tmp, { force: true });
  }
  return target;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const worker = process.argv[2] ?? "";
  try {
    console.log(`wrote ${generate(worker)}`);
  } catch (err) {
    console.error(`deploy config not generated:\n${(err as Error).message}\nSee .deploy.env.example.`);
    process.exit(1);
  }
}

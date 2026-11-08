/**
 * One-off full load of the advisory index. Runs on a laptop, not on Workers.
 *
 *   npm run bootstrap -- download
 *   npm run bootstrap -- generate [--limit N] [--out DIR]
 *   npm run bootstrap -- load --local|--remote [--dir DIR]
 *
 * `generate` is deterministic and uses the same distill() path as the refresh Workflow.
 * `load` is for a fresh database: it applies every migration in migrations/, then the data. It is resumable:
 * finished steps are recorded in <dir>/checkpoint.<local|remote>.json.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { ECOSYSTEMS as ECOSYSTEM_SPECS, ENABLED_ECOSYSTEMS, distill, buildKvEntry, kvKey, type Advisory, type OsvRecord } from "../packages/core/src/index.js";
import { loadDeployEnv } from "./lib/deploy-env.js";
import { listMigrations } from "./lib/migrations.js";
import { advisoryInsert, chunk, syncStateInsert } from "./lib/sql.js";
import { forEachJsonEntry, writeLines } from "./lib/zip.js";

const DATA = resolve("scripts/data");
const BASE = "https://osv-vulnerabilities.storage.googleapis.com";
const ECOSYSTEMS = ENABLED_ECOSYSTEMS.map((id) => ({ osv: ECOSYSTEM_SPECS[id].osvName, ours: id }));
const SQL_ROWS_PER_FILE = 10_000;
const KV_KEYS_PER_FILE = 10_000;
const CWE_FAMILY = ["CWE-506", "CWE-507", "CWE-510", "CWE-511", "CWE-912"];

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
}
const flag = (name: string): boolean => process.argv.includes(`--${name}`);

function run(cmd: string, args: string[], cwd?: string): void {
  const result = spawnSync(cmd, args, { stdio: "inherit", cwd });
  if (result.status !== 0) throw new Error(`${cmd} ${args.join(" ")} exited with ${result.status}`);
}

function download(): void {
  mkdirSync(DATA, { recursive: true });
  for (const { osv } of ECOSYSTEMS) {
    const target = join(DATA, `${osv}.zip`);
    if (existsSync(target)) {
      console.log(`skip ${osv}.zip (exists)`);
      continue;
    }
    console.log(`download ${osv}.zip`);
    run("curl", ["-fL", "--progress-bar", "-o", target, `${BASE}/${osv}/all.zip`]);
  }
}

async function generate(): Promise<void> {
  const out = resolve(arg("out") ?? join(DATA, "out"));
  const limit = arg("limit") ? Number(arg("limit")) : Infinity;
  rmSync(out, { recursive: true, force: true });
  mkdirSync(join(out, "sql"), { recursive: true });
  mkdirSync(join(out, "kv"), { recursive: true });

  const rows = new Map<string, Advisory>();
  const newest: Record<string, string> = {};
  const recordCount: Record<string, number> = {};
  const cweHits: Record<string, number> = Object.fromEntries(CWE_FAMILY.map((c) => [c, 0]));
  let skipped = 0;
  let malformed = 0;

  for (const { osv, ours } of ECOSYSTEMS) {
    const zipPath = join(DATA, `${osv}.zip`);
    if (!existsSync(zipPath)) throw new Error(`${zipPath} missing — run: npm run bootstrap -- download`);
    let seen = 0;
    const started = Date.now();
    const done = new Error("limit reached");

    try {
      await forEachJsonEntry(zipPath, (_name, json) => {
        if (seen >= limit) throw done;
        let record: OsvRecord;
        try {
          record = JSON.parse(json) as OsvRecord;
        } catch {
          malformed++;
          return;
        }
        if (typeof record.id !== "string" || typeof record.modified !== "string") {
          malformed++;
          return;
        }
        seen++;
        if (!newest[ours] || record.modified > newest[ours]) newest[ours] = record.modified;
        const advisories = distill(record);
        if (advisories.length === 0) skipped++;
        for (const advisory of advisories) {
          rows.set(`${advisory.ecosystem}|${advisory.osvId}|${advisory.packageName}`, advisory);
          for (const cwe of advisory.cweIds) if (cwe in cweHits) cweHits[cwe] = (cweHits[cwe] ?? 0) + 1;
        }
        if (seen % 25_000 === 0) console.log(`  ${osv}: ${seen} records, ${((Date.now() - started) / 1000).toFixed(0)}s`);
      });
    } catch (err) {
      if (err !== done) throw err;
    }
    recordCount[ours] = seen;
    console.log(`${osv}: ${seen} records in ${((Date.now() - started) / 1000).toFixed(1)}s`);
  }

  const all = [...rows.values()];
  let fileNo = 0;
  for (const part of chunk(all, SQL_ROWS_PER_FILE)) {
    fileNo++;
    await writeLines(join(out, "sql", `advisories-${String(fileNo).padStart(3, "0")}.sql`), part.map(advisoryInsert));
  }
  const syncedAt = new Date().toISOString();
  await writeLines(
    join(out, "sql", "zz-sync-state.sql"),
    ECOSYSTEMS.map(({ ours }) => syncStateInsert(ours, newest[ours] ?? "1970-01-01T00:00:00Z", recordCount[ours] ?? 0, syncedAt)),
  );

  const byKey = new Map<string, Advisory[]>();
  let oversizedKeys = 0;
  for (const advisory of all) {
    const key = kvKey(advisory.ecosystem, advisory.packageName);
    if (key === null) {
      oversizedKeys++;
      continue;
    }
    const list = byKey.get(key);
    if (list) list.push(advisory);
    else byKey.set(key, [advisory]);
  }
  const kvPairs: Array<{ key: string; value: string }> = [];
  for (const [key, advisories] of byKey) {
    const entry = buildKvEntry(advisories, syncedAt);
    if (entry) kvPairs.push({ key, value: JSON.stringify(entry) });
  }
  kvPairs.sort((a, b) => a.key.localeCompare(b.key));
  fileNo = 0;
  for (const part of chunk(kvPairs, KV_KEYS_PER_FILE)) {
    fileNo++;
    writeFileSync(join(out, "kv", `kv-${String(fileNo).padStart(3, "0")}.json`), JSON.stringify(part));
  }

  const kinds = { malware: 0, vulnerability: 0, withdrawn: 0 };
  for (const a of all) {
    kinds[a.kind]++;
    if (a.withdrawn) kinds.withdrawn++;
  }
  const stats = {
    generatedAt: syncedAt,
    recordCount,
    newest,
    advisoryRows: all.length,
    kvKeys: kvPairs.length,
    kinds,
    cweFamilyHits: cweHits,
    recordsWithNoInScopePackage: skipped,
    malformedRecords: malformed,
    oversizedKeys,
  };
  writeFileSync(join(out, "stats.json"), JSON.stringify(stats, null, 2));
  console.log(JSON.stringify(stats, null, 2));
}

interface Checkpoint {
  done: string[];
}

function load(): void {
  const dir = resolve(arg("dir") ?? join(DATA, "out"));
  const remote = flag("remote");
  if (remote === flag("local")) throw new Error("Pass exactly one of --local or --remote");
  if (!existsSync(join(dir, "stats.json"))) throw new Error(`${dir} has no generated output — run generate first`);

  const env = loadDeployEnv(["PKGGUARD_ACCOUNT_ID", "PKGGUARD_D1_ID", "PKGGUARD_KV_ID"]);
  const configPath = join(dir, "wrangler.bootstrap.jsonc");
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        name: "pkgguard-bootstrap",
        account_id: env["PKGGUARD_ACCOUNT_ID"],
        compatibility_date: "2026-11-06",
        d1_databases: [{ binding: "DB", database_name: "pkgguard-db", database_id: env["PKGGUARD_D1_ID"] }],
        kv_namespaces: [{ binding: "PKG_INDEX", id: env["PKGGUARD_KV_ID"] }],
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );

  const checkpointPath = join(dir, `checkpoint.${remote ? "remote" : "local"}.json`);
  const checkpoint: Checkpoint = existsSync(checkpointPath)
    ? (JSON.parse(readFileSync(checkpointPath, "utf8")) as Checkpoint)
    : { done: [] };
  const step = (id: string, fn: () => void): void => {
    if (checkpoint.done.includes(id)) {
      console.log(`skip ${id} (done)`);
      return;
    }
    console.log(`run  ${id}`);
    fn();
    checkpoint.done.push(id);
    writeFileSync(checkpointPath, JSON.stringify(checkpoint, null, 2));
  };

  const target = remote ? ["--remote"] : ["--local", "--persist-to", join(dir, ".wrangler-local")];
  // Unset in the child env: wrangler reserves this variable and would abandon its OAuth session.
  delete process.env["CLOUDFLARE_API_TOKEN"];
  const wrangler = (args: string[]): void => run("npx", ["wrangler", ...args, "-c", configPath, ...target]);

  // Every migration, in order: the Workers expect the whole schema, and a missing table or column only shows up as a
  // background write that fails silently.
  const migrations = resolve("migrations");
  for (const file of listMigrations(migrations)) {
    step(`migration:${file}`, () => wrangler(["d1", "execute", "pkgguard-db", "--file", join(migrations, file)]));
  }
  for (const file of readdirSync(join(dir, "sql")).sort()) {
    step(`sql:${file}`, () => wrangler(["d1", "execute", "pkgguard-db", "--file", join(dir, "sql", file), "-y"]));
  }
  for (const file of readdirSync(join(dir, "kv")).sort()) {
    step(`kv:${file}`, () => wrangler(["kv", "bulk", "put", join(dir, "kv", file), "--binding", "PKG_INDEX"]));
  }
  console.log("load complete");
}

const command = process.argv[2];
if (command === "download") download();
else if (command === "generate") await generate();
else if (command === "load") load();
else {
  console.error("usage: bootstrap <download|generate|load>");
  process.exit(2);
}

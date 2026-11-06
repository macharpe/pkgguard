# AGENTS.md — PkgGuard

Guidance for a coding agent working in this repository. This file is published: it must never contain real account IDs, hostnames, emails or filesystem paths.

> **Status: skeleton.** Sections marked _TBD_ are filled in as the milestones that own them land. Keep the invariants current.

## Purpose

PkgGuard enforces OSV.dev supply-chain data on package downloads through a Cloudflare Gateway **Forward** Worker. Gateway invokes the Worker on package traffic; the Worker looks the package up in an OSV-derived index and blocks malware while logging vulnerabilities. A second Worker serves an Access-protected admin UI and runs the refresh Workflow.

## Architecture

- `pkgguard-filter` — `GatewayMiddleware` entrypoint only. No public route. Hot path.
- `pkgguard-admin` — admin UI, REST API, `RefreshWorkflow`, crons. Behind Cloudflare Access on a custom domain.
- `packages/core` — pure TypeScript with no Workers APIs: URL parsers, version comparators, OSV classification and range matching. Shared by both Workers and the bootstrap script.
- D1 is the source of truth and powers the UI. KV holds a flattened `ecosystem:name` index for hot-path reads.

## Invariants — do not break

- The exported class name `GatewayMiddleware` is load-bearing. Gateway invokes it by name over Workers RPC. Renaming it silently breaks enforcement.
- Call `next()` **at most once** per invocation. Never twice, never concurrently.
- The filter Worker fails **open** on any internal error. Gateway itself fails **closed** on Worker errors, so an uncaught throw blocks the user's download. Wrap every code path.
- Malware classification is the CWE rule in `packages/core/src/osv/classify.ts`, **not** the `MAL-` ID prefix. `event-stream` is the regression test; it has no `MAL-` ID.
- D1 allows **100 bound parameters per query**. Use `db.batch()` of single-row statements, never a wide multi-row `INSERT`.
- KV allows **1,000 operations per invocation**. Chunk sync steps accordingly.
- Workflow step results are capped at **1 MiB**. Return counts from steps, never record arrays.
- Never export `CLOUDFLARE_API_TOKEN`. Wrangler reserves it and will abandon its OAuth session.
- `workers_dev` and `preview_urls` stay `false` on the filter Worker.
- Deleting the filter Worker does **not** disable a live Forward policy; matching requests then return 500. Update or delete the policy first.
- Gateway only classifies a package download if the registry host is TLS-decrypted. A Do Not Inspect rule covering the registry's app silently disables enforcement for that ecosystem.
- Real account IDs, hostnames and secrets never enter a tracked file. Edit `wrangler.jsonc` (placeholders), never `wrangler.local.jsonc` (generated).

## Commands

| Command | Purpose |
|---|---|
| `npm install` | Install the workspace |
| `npm test` | Full test suite — never filter |
| `npm run test:coverage` | Same, with v8 coverage |
| `npm run typecheck` | `tsc --noEmit` over `packages/core` and `scripts` |
| `npm run bootstrap -- download` | Fetch the npm and PyPI OSV zips into `scripts/data/` (gitignored) |
| `npm run bootstrap -- generate [--limit N] [--out DIR]` | Distill the zips into SQL chunks and KV bulk files |
| `npm run bootstrap -- load --local\|--remote [--dir DIR]` | Apply the migration and load. Resumable via `<dir>/checkpoint.*.json`. Test with `--limit` and `--local` first. |

_TBD:_ `deploy` and `terraform -chdir=terraform plan` arrive with their milestones.

## Layout

```
packages/core/            pure TS, no Workers APIs
  src/normalize.ts          name normalization + KV key
  src/parse/                registry URL -> {ecosystem, namespace, name, version}
  src/version/              SemVer (npm) and PEP 440 (PyPI) comparison
  src/osv/                  classify, match, distill, KV entry + evaluate
  test/fixtures/            real OSV records, committed as-is
```

`scripts/` holds the one-off bootstrap (`bootstrap.ts`, `lib/`). `migrations/0001_init.sql` is the D1 schema.

_TBD:_ `workers/filter`, `workers/admin`, `terraform`.

Two non-obvious rules in `core`: an **unparseable version never matches** (it is not "equal" and not "affected"), and **one OSV record yields one advisory row per affected package** — event-stream and flatmap-stream share a record.

## Configuration

Values come from the environment, falling back to `.deploy.env`. Copy `.deploy.env.example` to `.deploy.env` and fill it in. The deploy config (`wrangler.local.jsonc`) is generated before each deploy and is gitignored. Local secrets go in `.dev.vars`; copy `.dev.vars.example`.

## Testing

Vitest with `@cloudflare/vitest-pool-workers`. `npm test` must always run in full with no name filter; a "pattern not found" result is a failure, not a pass. Mandatory classifier fixtures (each pinned to a real OSV ID): `event-stream` GHSA-mh6f-8j2x-4483, `coa` GHSA-73qr-pfmq-6rp8, `ctx` GHSA-4g82-3jcr-q52w, `@solana/web3.js` MAL-2024-11183, `node-ipc` MAL-2026-3744 — all malware — and `ua-parser-js` GHSA-394c-5j6w-4xmx as the **vulnerability** negative control.

## Git hygiene

Never `git add -A`. Add explicit paths and read the full `git status --porcelain`, including untracked files, before any commit.

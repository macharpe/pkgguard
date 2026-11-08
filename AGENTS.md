# AGENTS.md — PkgGuard

Guidance for a coding agent working in this repository. This file is published: it must never contain real account IDs, hostnames, emails or filesystem paths.

> **Status: in progress.** The filter Worker, Terraform, the Gateway rule script and the admin API and dashboard exist. The refresh Workflow, overrides and alerts are still to come. Keep the invariants current.

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
- `ENFORCE` blocks only when it is exactly the string `"true"`. With any other value the filter is observe-only, and a would-be block is recorded as `flagged`, never `blocked`. The committed template stays `"false"`, so a fresh checkout never blocks; the live value is `PKGGUARD_ENFORCE` in `.deploy.env`, applied by the config generator (`applyEnforce`), so a redeploy cannot silently switch it back. Anything but exactly `true` or `false` is an error, and every deploy prints the mode it wrote. Do not edit `ENFORCE` in `wrangler.jsonc`.
- `OBSERVE_ONLY` is a comma-separated list of ecosystem ids that never block, whatever `ENFORCE` says; a would-be block there is recorded `flagged`. A new ecosystem starts in it. It comes from `PKGGUARD_OBSERVE_ONLY` through `applyObserveOnly`, which refuses an unknown id (a typo must never mean "block"); the Worker ignores unknown ids. Do not edit it in `wrangler.jsonc`.
- `Decision.block` is policy; whether a download is stopped is `block && enforces(ecosystem)`, where `enforces` is `ENFORCE` and not observe-only for that ecosystem. Keep those separate.
- An ecosystem is a registry entry, never a branch. `ECOSYSTEM_IDS`, `ENABLED_ECOSYSTEMS` and the labels live in `packages/core/src/ecosystem-ids.ts`, which imports nothing, so the dashboard can use it without the comparators (import it as `@pkgguard/core/ecosystems`); everything else about an ecosystem is its spec in `packages/core/src/ecosystems/`. Never write `ecosystem === "pypi" ? … : …`: adding an id must fail to compile until it has a spec, a label and a fixture in `ecosystems.test.ts`. Defined is not enabled: load an ecosystem's data (`bootstrap … --ecosystem`), then enable it, then widen the Forward rule.
- `distill(record)` takes one argument because `live.ts` passes it to `flatMap`, which would hand it an index. Use `distillFor(record, ecosystems)` to choose. SQL that filters by ecosystem uses `enabledEcosystemSqlList()`: a literal list, because D1 allows 100 bound parameters and those queries already bind about 90.
- The live OSV lookup runs only on an index miss, and an incomplete answer (pagination, malformed records) is never cached.
- Resolve `context.identity()` before returning from `handle`. The context's RPC stubs are not guaranteed to outlive the call, so it cannot be deferred into `waitUntil`.
- Call the global `fetch` through a wrapper, never as a stored property: workerd throws Illegal invocation otherwise.
- Deleting the filter Worker does **not** disable a live Forward policy; matching requests then return 500. Update or delete the policy first (`npm run gateway:rule -- delete`).
- The Forward rule is always scoped to `PKGGUARD_SCOPE` (emails and/or `@domain` entries; an empty value is an error) and always created disabled. A domain renders as `identity.email matches "(?i)^[^@]+@domain[.]tld$"`, which Gateway accepts and applies, verified live. Scope is decided at Gateway, never in the Worker. Traffic with no identity (no WARP session, proxy-endpoint mode) does not match, so it is not filtered: that is a property of scoping by identity. Its precedence must stay above the static `pkg.*` policies (46500).
- There is one Access application for the admin hostname, covering people and the service token. Never add a second application on the same hostname (see the admin invariants).
- Gateway only classifies a package download if the registry host is TLS-decrypted. A Do Not Inspect rule covering the registry's app silently disables enforcement for that ecosystem.
- Real account IDs, hostnames and secrets never enter a tracked file. Edit `wrangler.jsonc` (placeholders), never `wrangler.local.jsonc` (generated). Every placeholder is distinct and format-valid; adding a new one means adding it to `scripts/lib/deploy-config.ts` and to the worker's expected counts there.

## Commands

| Command | Purpose |
|---|---|
| `npm install` | Install the workspace |
| `npm test` | Full test suite — never filter |
| `npm run test:coverage` | Same, with v8 coverage |
| `npm run typecheck` | `tsc --noEmit` over `packages/core`, `scripts` and `workers/filter` |
| `npm run bootstrap -- download [--ecosystem E]` | Fetch the OSV zips into `scripts/data/` (gitignored): every enabled ecosystem, or the one named (by id or OSV name, and it may be defined but not yet enabled) |
| `npm run bootstrap -- census [--ecosystem E] [--json]` | Before loading: unreadable range boundaries and listed versions, names merged by normalisation, over-long KV keys, records that would abort a batch, malware by prefix against CWE rule. Review it. |
| `npm run bootstrap -- generate [--ecosystem E] [--limit N] [--out DIR]` | Distill the zips into SQL chunks and KV bulk files. `--ecosystem` writes to `out-<id>`, never over the full index. |
| `npm run bootstrap -- load --local\|--remote [--ecosystem E] [--dir DIR] [--force]` | Without `--ecosystem`, for a **fresh** database: apply every migration in `migrations/` in order (numbering must have no gap), then load. With it: data only, into a database that exists; refuses an ecosystem that already has sync state unless `--force`, and a directory generated for other ecosystems. Resumable via `<dir>/checkpoint.*.json`. Test with `--limit` and `--local` first. |
| `npm run deploy:config:filter` | Generate `workers/filter/wrangler.local.jsonc` from the template and `.deploy.env`. Fails on any placeholder. |
| `npm run deploy:filter` | Generate the config, then `wrangler deploy` with `CLOUDFLARE_API_TOKEN` unset |
| `wrangler d1 execute pkgguard-db --remote -c workers/filter/wrangler.local.jsonc --file migrations/<n>.sql` | Apply a migration. They are not applied automatically. Record `wrangler d1 time-travel info pkgguard-db` first. |
| `npm run build:admin` | Build the dashboard into `workers/admin/dist` (gitignored) |
| `npm run deploy:admin` | Build the dashboard, generate the admin config, then `wrangler deploy`. Always builds first. |
| `npm run gateway:rule -- status\|create\|enable\|disable\|sync\|delete` | Manage the Gateway Forward rule. `create` always makes it disabled. `sync` writes the desired rule (traffic follows the enabled ecosystems), printing each field it changes, and never changes whether the rule is enabled. Needs `TF_VAR_cloudflare_api_token` in the environment. |
| `terraform -chdir=terraform plan -out=tfplan` | Access apps, policies and service token. Never apply without a reviewed plan. |

## Layout

```
packages/core/            pure TS, no Workers APIs
  src/ecosystem-ids.ts      ids, enabled list, labels: data only, imports nothing
  src/ecosystems/           one spec per ecosystem + the registry
  src/normalize.ts          name normalization + KV key, through the registry
  src/parse/                registry URL -> {ecosystem, namespace, name, version}
  src/version/              SemVer (npm) and PEP 440 (PyPI) comparison
  src/osv/                  classify, match, distill, KV entry + evaluate
  test/fixtures/            real OSV records, committed as-is
```

`scripts/` holds the one-off bootstrap (`bootstrap.ts`) and the deploy-config generator (`generate-deploy-config.ts`); shared code is in `scripts/lib/`. `workers/<name>/wrangler.jsonc` is the committed template with placeholder IDs. `migrations/0001_init.sql` is the D1 schema.

```
workers/filter/           pkgguard-filter
  src/index.ts              GatewayMiddleware: parse, decide, record, block or next()
  src/decide.ts             overrides -> KV index -> live OSV; returns a Decision
  src/osv-client.ts         api.osv.dev query with a timeout
  src/detections.ts         D1 insert
  src/page.ts               403 coaching page
  test/                     Workers-runtime tests: real KV, real D1 with the migration applied
```

`terraform/` holds the Access side. The Gateway Forward rule is **not** in Terraform: provider 5.28.x has no `forward` action, so `scripts/gateway-rule.ts` manages it through the API.

```
workers/admin/            pkgguard-admin
  src/index.ts              handle(): authenticate, route, error-to-JSON. Default export is a thin wrapper.
  src/access-jwt.ts         Access JWT verification (RS256 only, JWKS cache, fails closed)
  src/api/                  status, detections, advisories, whoami, refresh
  src/refresh/              the refresh pipeline: iso, modified-csv, osv-fetch, apply, plan, batch, runs, launch, workflow
  src/api-types.ts          the API contract: type-only, shared with the dashboard
  ui/                       React + Vite + Kumo dashboard (own tsconfig, DOM types); builds to dist/
  test/                     Workers-runtime tests; assets-real.test.ts needs `npm run build:admin` first
```

Admin invariants: the dashboard and `/api/*` are **one Access application with one audience**. Do not split them: a second application on the same hostname shares the `CF_Authorization` cookie name but has a different audience, so the browser session earned on the dashboard is rejected on `/api/*` and the dashboard's own `fetch()` calls bounce to login. A service-token JWT has `common_name` and no `email`, and Access cannot scope it by path inside one application, so the Worker refuses a service token everywhere except `/api/` (`authenticate`). Every non-API GET is served from the `ASSETS` binding only after the JWT is verified, and the CSP is set by response content type, not by URL, because the page is requested as `/`. The CSP forbids inline script, so the theme bootstrap is the external `theme-init.js`. The UI must treat an opaque redirect (Access sending an expired session to login) as "session ended", and hide its panels rather than show an empty state.

HTTP methods: the API uses only GET and POST. The zone's managed WAF blocks every other method (`Anomaly:Method - Not GET or POST`) before it reaches the Worker, so the dashboard's Remove button would fail on a `DELETE` even though local tests pass. Removal is `POST /api/overrides/remove`. A local mock cannot reveal this: verify any new write against the deployed hostname.

Alert invariants: an alert must never affect a download or a refresh: it runs in `waitUntil` or its own Workflow step and swallows every error. Malware alerts are limited to one per package **per user** per hour (`malwareAlertKey`; unidentified downloads share one bucket, so they are still limited). A failed send shortens the key to 60 s so it is retried soon rather than lost for an hour. KV keys are limited to 512 bytes, not characters: `malwareAlertKey` budgets its parts in bytes. `sendChat` only posts to a genuine Chat incoming-webhook URL and never logs it; anything from a request or a person goes through `safeToken` or `safeText`. The webhook is a Worker secret, never in `wrangler.jsonc`.

Block-response invariants: what a blocked developer sees depends on the client, and `Accept` cannot tell them apart because npm and pip both send `*/*` on a download, so the User-Agent decides (`clientKind` in `workers/filter/src/page.ts`). Verified against real npm 11 and pip 26 **behind Gateway**, not assumed: npm appends the `error` field of a JSON body to its error line, which is the only channel that reaches an npm terminal; pip prints only `403 Client Error: Forbidden`, so nothing in the response reaches a pip terminal; Gateway replaces the HTTP reason phrase with the standard one (a local mock keeps it, which is why it must be tested through Gateway); curl prints the plain-text body; only a browser gets the HTML page. A pip user learns the detail from the Chat alert or the dashboard. Everything shown is built from `safeToken`/`safeText` output, the reason phrase is visible ASCII only, and the page is inline-only under `default-src 'none'`. Each malware decision gets one `PG-XXXXXX` reference (`newReference` in `core`), written to the `detections.reference` column, the response header and body, and the Chat alert, so the code a developer quotes finds the row (`GET /api/detections?reference=`). Observe-only decisions get one too.

Refresh invariants: the high-water mark (`sync_state.last_modified`) must never advance past a record that failed to fetch, so `advanceHighWater` stops just before the oldest failure. OSV timestamps mix precisions, so compare them with `normalizeIso`, never as strings. `applyRecords` deletes a record's old rows before inserting, and rebuilds KV for every touched package from D1 (D1 is the source of truth, KV is derived). `advisoryRow` in `core` is the only definition of how an advisory becomes a row; the bootstrap and the Workflow both use it. A step result is capped at 1 MiB, so the work list lives in `refresh_items`. Only one run is active at a time, enforced in a single `INSERT ... WHERE NOT EXISTS`. Every write endpoint requires the `x-pkgguard-csrf: 1` header, because the Access cookie is sent cross-site. A delta over 20,000 records is refused: that is a rebuild, which is the bootstrap's job.

Two non-obvious rules in `core`: an **unparseable version never matches** (it is not "equal" and not "affected"), and **one OSV record yields one advisory row per affected package** — event-stream and flatmap-stream share a record.

## Configuration

Values come from the environment, falling back to `.deploy.env`. Copy `.deploy.env.example` to `.deploy.env` and fill it in. The deploy config (`wrangler.local.jsonc`) is generated before each deploy and is gitignored. Secrets such as `GCHAT_WEBHOOK` are Worker secrets set with `wrangler secret put`; for local runs they go in the gitignored `.dev.vars`.

## Testing

Vitest with `@cloudflare/vitest-pool-workers`. `npm test` must always run in full with no name filter; a "pattern not found" result is a failure, not a pass. Mandatory classifier fixtures (each pinned to a real OSV ID): `event-stream` GHSA-mh6f-8j2x-4483, `coa` GHSA-73qr-pfmq-6rp8, `ctx` GHSA-4g82-3jcr-q52w, `@solana/web3.js` MAL-2024-11183, `node-ipc` MAL-2026-3744 — all malware — and `ua-parser-js` GHSA-394c-5j6w-4xmx as the **vulnerability** negative control.

## Git hygiene

Never `git add -A`. Add explicit paths and read the full `git status --porcelain`, including untracked files, before any commit.

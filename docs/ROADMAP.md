# Roadmap: RubyGems, Cargo, Go and NuGet

Status: **proposal, not started.** PkgGuard enforces npm and PyPI today. This document is the plan for adding four more ecosystems: Cargo, RubyGems, NuGet and Go, in that order.

**Maven is deliberately out of scope**, for two measured reasons recorded in [Maven](#maven-out-of-scope). The decision can be revisited.

Everything marked *measured* was taken from the live OSV feeds and registries on 2026-11-07. Anything not measured is labelled *unverified* and has a test that will settle it. Section [Method](#method) says how to repeat the measurements.

## Contents

1. [Summary](#summary)
2. [What each ecosystem buys](#what-each-ecosystem-buys)
3. [Maven: out of scope](#maven-out-of-scope)
4. [Findings that shape the design](#findings-that-shape-the-design)
5. [Phase 0: make "ecosystem" a registry](#phase-0-make-ecosystem-a-registry)
6. [Per-ecosystem designs](#per-ecosystem-designs)
7. [Cross-cutting work](#cross-cutting-work)
8. [Order of operations for each ecosystem](#order-of-operations-for-each-ecosystem)
9. [Test environment and procedure](#test-environment-and-procedure)
10. [Definition of done](#definition-of-done)
11. [Decisions needed](#decisions-needed)
12. [Risks and open questions](#risks-and-open-questions)
13. [Method](#method)

## Summary

| Phase | Content | New malware coverage |
|---|---|---:|
| 0 | Ecosystem registry refactor, plus the tooling the later phases depend on. No new ecosystem, no behaviour change. | 0 |
| 1 | **Cargo**: the pilot, on a feed where a mistake blocks almost nothing. Also settles the Gateway classification question. | 28 |
| 2a | **RubyGems**: the largest malware feed of the four. | 4,311 |
| 2b | **NuGet**: the hardest comparator of the four. | 782 |
| 3 | **Go**: mostly a vulnerability-logging feature. | 21 |

Three things drive the plan, and each is argued with data below:

1. **The code is small; the unknowns are in the clients and in Gateway.** Each new ecosystem needs a real toolchain exercised behind Gateway, because what a blocked developer sees differs per client.
2. **NuGet and RubyGems cannot reuse `compareSemver`.** The measured cost of getting it wrong is smaller than it first looked, and falls on vulnerability flagging, not on malware blocking: no malware advisory in any of the four feeds depends on a version boundary the SemVer comparator cannot read (see [Versions](#versions-two-comparators-cannot-reuse-comparesemver)).
3. **Name identity differs in all four**, and getting it wrong either misses real malware (NuGet) or merges distinct packages (RubyGems, Go).

## What each ecosystem buys

Measured. "Malware" applies the repository's classifier: the `MAL-` ID prefix **or** a CWE in the malware family (see `packages/core/src/osv/classify.ts`).

| OSV ecosystem | Records | `all.zip` | Distinct package names | Malware | Of which `MAL-` | Value |
|---|---:|---:|---:|---:|---:|---|
| npm *(shipped)* | 231,292 | 210 MB | n/a | n/a | 223,207 | |
| PyPI *(shipped)* | 26,816 | 36 MB | n/a | n/a | 12,000 | |
| RubyGems | 5,477 | 5.0 MB | 4,750 | 4,311 | 4,311 | Blocking and logging |
| NuGet | 1,971 | 2.6 MB | 1,464 | 782 | 782 | Blocking and logging |
| crates.io | 3,055 | 3.6 MB | 1,711 | 28 | 21 | Mostly logging (see below) |
| Go | 9,914 | 12.2 MB | 1,673 | 21 | 20 | Mostly logging |

- **Volume is a non-issue.** The four add about 23 MB and about 20,400 records to roughly 246 MB and 258,000. About 9,600 more KV keys; no schema change (`ecosystem` is already `TEXT`).
- **The blocking value is concentrated in RubyGems and NuGet.** Cargo and Go are, in practice, vulnerability-logging features, which PkgGuard does by design (CVEs are logged, never blocked).
- **Cargo's malware records describe packages crates.io has already removed.** All seven records that only the CWE rule finds (`GHSA-6v2j-vr4h-f632` and six others) read "was removed from crates.io for malicious code". Blocking them is of little use against the public registry, and of real use only against a mirror or cache that still serves them.
- **Most of these malware records describe packages the registry has already removed.** *Measured* with metadata requests only (nothing downloaded): none of Cargo's 28 and none of Go's 21 can still be downloaded, and none of a random 80 each from RubyGems and NuGet. A public-registry block therefore matters only in the window between an OSV record appearing and the registry removing the package; that window was not measured. The blocking value is larger against **mirrors and caches** (Artifactory, Nexus and similar), which Gateway classifies by URL shape and which can keep serving a package the registry has dropped. Weigh the malware counts above with this in mind.
- **The CWE rule earns its keep again.** Seven of Cargo's 28 would be missed by a `MAL-` prefix check. This is the same lesson as `event-stream`.

## Maven: out of scope

Two measured reasons:

- **Almost no blocking value.** The Maven feed has **2** `MAL-` records in 7,253. Adding it is a CVE-logging feature only.
- **The hardest comparator, and the only one that cannot be derived from a spec alone.** Maven's `ComparableVersion` has a qualifier ordering (`alpha` < `beta` < `milestone` < `rc` < `snapshot` < release < `sp`), aliases, and trailing-zero rules. A faithful port needs a differential test against the reference implementation. It is also the only ecosystem whose identity is two fields (`group:artifact`), which would break the single-string KV key shape (`ecosystem:name`) that the other four fit.

Revisit if a customer needs Java coverage badly enough to justify the comparator work, or if Maven's malware feed grows.

## Findings that shape the design

### Name identity differs in all four

The index key is `ecosystem:normalizedName`, and the lookup builds it from the **download URL**, while the index is built from **OSV's names**. Both sides must normalise to the same string, and the normalisation must never merge two distinct packages.

| Ecosystem | What the registry treats as identity | Measured in OSV | Chosen normalisation |
|---|---|---|---|
| NuGet | Case-insensitive | 1,376 of 1,464 names contain uppercase; **33** names appear under more than one casing (for example `Dnn.Platform` and `DNN.PLATFORM`) | Lowercase both sides; merge the variants' advisories |
| Cargo | Case-insensitive; `-` and `_` equivalent | 5 uppercase names; 4 case collisions, 6 once `-`/`_` is folded (for example `Deno` and `deno`) | Lowercase, and `_` to `-` |
| RubyGems | Case-sensitive; `-` and `_` are **different** gems | 18 uppercase names, **0** lowercase collisions; **23** pairs that differ only by `-` versus `_` (for example `3scale-time-range` and `3scale-time_range`) | Lowercase only. Never fold `-`/`_` |
| Go | Case-sensitive, exact module path | 105 names contain uppercase; **8** pairs differ only by case (for example `github.com/BishopFox/sliver` and `github.com/bishopfox/sliver`) | None. Exact path, after decoding the proxy's `!` escapes |

Why this matters:

- **NuGet is the silent-miss trap.** The download URL is always lowercase (a mixed-case URL returns 404, measured), but 94% of OSV's NuGet names are mixed case. Building the key from the raw OSV name would make most lookups miss with no error.
- **RubyGems and Go are the over-merge trap.** Folding `-`/`_` for RubyGems, or case for Go, would let one package's advisory apply to a different package.
- **No name approaches the KV key limit.** The longest measured key is 94 bytes against the 512-byte cap.

### Versions: two comparators cannot reuse `compareSemver`

`compareSemver` returns `null` for a string `semver.parse` rejects, and the matcher treats `null` as "never matches" (`packages/core/src/osv/match.ts`). What that costs depends on where the unreadable string sits in an advisory:

- **A range boundary** (`introduced`, `fixed`, `last_affected`). The comparator cannot place the version being checked against it, so **the whole range never matches**. An advisory with `fixed: "1.90"` flags nothing below it.
- **An explicit `versions` list.** The matcher checks string equality first, so the identical string still matches. Only a differently written equal version would miss.

*Measured* with `bootstrap census` for npm and PyPI, and with the repository's `semver` dependency for the four candidates (every string in each feed, excluding OSV's `"0"` for "the beginning of time"):

| Ecosystem | Unreadable range boundaries | Of those, in malware advisories | Unreadable listed versions |
|---|---:|---:|---:|
| NuGet | 84 of 11,375 (0.7%) | **0** | 139,309 of 517,601 (26.9%) |
| RubyGems | 512 of 2,927 (**17.5%**) | **0** | 21,371 of 86,123 (24.8%) |
| Go | 68 of 20,266 (0.3%) | **0** | 4 of 200 (2.0%) |
| Cargo | 10 of 6,343 (0.2%) | **0** | 2 of 132 (1.5%) |
| *npm (today)* | 30 of 16,667 (0.2%) | **0** | 2 of 54,562 |
| *PyPI (today)* | 53 of 34,204 (0.2%) | **0** | 2,843 of 1,457,499 (0.2%) |

What this says:

- **Blocking malware does not depend on the new comparators.** Across all six ecosystems, no unreadable range boundary sits in a malware advisory. Malware records match through a listed version or through "every version", neither of which needs ordering.
- **Flagging vulnerabilities does.** RubyGems is the clear case: 17.5% of its range boundaries (for example `3.0.4.1`, `1.5.0.beta.1`) cannot be read by the SemVer comparator, so those ranges never flag. NuGet's range boundaries are mostly readable (0.7%).
- **The listed-version figure still matters for NuGet**, in a different way. NuGet's URL carries a *normalised* version (a fourth zero part dropped, build metadata removed), so a listed `1.0.0.0` and a URL `1.0.0` are the same version written two ways, and only a NuGet comparator knows it.
- **This corrects an earlier version of this document,** which counted both kinds together (26.4% for NuGet, 24.6% for RubyGems) and described all of it as a silent miss.

Also *measured*, with the repository's `semver` dependency: it accepts the `v` prefix, accepts `+incompatible` build metadata (equal to the bare version), and accepts Go pseudo-versions (`v0.0.0-20210101000000-abcdef123456`). It compares prerelease labels case-sensitively (`1.0.0-RC1` is not equal to `1.0.0-rc1`), which NuGet does not.

Cargo's and Go's unreadable boundaries (10 and 68) are OSV-side strings that are not valid SemVer, such as `0.65`. Whether to coerce them on the OSV side only is a decision: see [Decisions needed](#decisions-needed).

### RubyGems: the name/version split is ambiguous, in both directions

Gem files are `{name}-{version}[-{platform}].gem`. Hyphens separate all three parts, and names and platforms can both contain digits.

- **Names that look like a version.** Three names in the feed end in a version-looking token: `gemxy-1778522681`, `southnews-test-35329`, `zztemp-ssf-2605`. **All three are malware records** (`MAL-2026-7711`, `MAL-2026-8836`, `MAL-2026-9976`). A parser that takes the first version-looking token splits `gemxy-1778522681-1.0.0.gem` wrongly and never looks the right name up.
- **Platforms that end in a number.** The real gem index has platform suffixes such as `x86_64-darwin-19` (177 lines of the index contain `-darwin-NN`). A parser that takes the *last* version-looking token picks `19` as the version.

Neither "first" nor "last" is right. The design is to **return every plausible split as a candidate and let the index decide** (see [RubyGems](#phase-2a-rubygems)).

### Go: the feed contains records that can never match, and one parser collision exists today

- **Inert records.** The Go feed has 188 `stdlib` entries and 34 `toolchain` entries, plus 12 with malformed names (`net/http`, `Traefik`, `sftpgo`, two full `https://` URLs, and others). None has a host in the first path element, so no module download can match them.
- **A real mis-parse in the current code.** *Measured by running the existing parser:* the Go proxy URL `.../github.com/foo/packages/bar/@v/v0.0.0-20210101000000-0123456789ab.zip` is parsed by `parsePypiUrl` as a **PyPI** package named `v0.0.0-20210101000000`, version `0123456789ab`. PyPI accepts any `.zip` under a path containing `/packages/`. Today this cannot occur because Go is not handled. The moment it is, ecosystem dispatch must be anchored on shape: Go on `/@v/`, and PyPI must refuse a path containing it.

### Cargo: the documented URL is not the one the client requests

Cloudflare's documented Cargo shape is `/crates/{name}/{name}-{version}.crate`. *Measured:*

- `static.crates.io/crates/serde/serde-1.0.200.crate` returns 200, and `crates.io/api/v1/crates/serde/1.0.200/download` redirects (302) to that shape.
- The index's `config.json` is `{"dl": "https://static.crates.io/crates", ...}` with no URL markers. The Cargo Book says a `dl` without markers makes Cargo request `{dl}/{crate}/{version}/download`; that is from its documentation, not something observed here. That shape does return 200 on `static.crates.io` (measured), but it is **not** the shape Cloudflare documents.

So there are two URL shapes, and Gateway's classifier is documented for only one. Whether Gateway classifies `/{crate}/{version}/download` is **unverified and gates the Cargo phase**: if it does not, the Forward rule never fires for real `cargo` traffic, and no Worker code can fix that. See the spike in [Phase 1](#phase-1-cargo).

### Failure modes in the current code that are silent

These are the reason Phase 0 exists. Each is a place where adding an ecosystem to a union type without touching a second spot gives no compile error and no runtime error.

| Where | What happens if the new ecosystem is not wired in |
|---|---|
| `workers/admin/src/refresh/apply.ts`: two literal `ecosystem IN ('npm','pypi')` clauses | The "replace this record's old rows" delete skips the new ecosystem, so stale advisories persist after a record changes |
| `packages/core/src/osv/advisory-row.ts`: `advisoryFromRow` accepts only `npm` and `pypi` | KV rebuild silently drops the new ecosystem's rows (counted in `unreadableRows`, never surfaced as a failure) |
| `workers/admin/src/refresh/plan.ts`: `planRun` throws `no sync state for X: run the bootstrap first` | Enabling an ecosystem in code before its data is loaded **fails the entire refresh run**, for every ecosystem, not just the new one |
| `workers/filter/src/index.ts`: a URL no parser accepts returns `next(request)` with no log | A disagreement between Gateway's classifier and ours is invisible |
| `scripts/lib/gateway-rule.ts`: `findRule` matches by **name**, and the name contains "npm and PyPI" | Renaming the rule orphans the live one; `status` says absent and `create` collides on precedence |

## Phase 0: make "ecosystem" a registry

A refactor with no behaviour change. It ships on its own, with no release tag, before any new ecosystem.

### The registry

One record per ecosystem in `packages/core/src/ecosystems.ts`, and `Ecosystem` derived from it:

```ts
export interface EcosystemSpec {
  id: Ecosystem;                      // "npm", "pypi", "cargo", "rubygems", "nuget", "go"
  label: string;                      // "PyPI", "Cargo", ...: replaces every `=== "pypi" ? "PyPI" : "npm"`
  osvName: string;                    // "PyPI", "crates.io", "RubyGems", "NuGet", "Go"
  gatewayName: string;                // the pkg.ecosystem value; see Cross-cutting
  purlType: string;
  normalizeName(raw: string): string;
  compare(a: string, b: string): -1 | 0 | 1 | null;
  namespaceOf(normalizedName: string): string | null;
  overrideNamePattern: RegExp;
  parse(url: URL): ParsedPackage[];   // a list: see below
}
```

Every `ecosystem === "pypi" ? … : …` in the code base is then deleted rather than extended. Call sites to convert, from a search of the current tree:

| Area | Files |
|---|---|
| core | `normalize.ts`, `version/index.ts`, `parse/index.ts` (including `toPurl`), `osv/distill.ts`, `osv/live.ts`, `osv/advisory-row.ts`, `notify.ts` (two types and two label ternaries) |
| admin | `api-types.ts`, `overrides.ts`, `api/detections.ts`, `api/advisories.ts`, `refresh/plan.ts`, `refresh/osv-fetch.ts`, `refresh/apply.ts` (the two SQL literals: generate the `IN (...)` list from the registry) |
| admin UI | `PackageLookup.tsx`, `OverridesPanel.tsx`, `DetectionsFeed.tsx`, `StatusCards.tsx` (hard-codes `npm … · PyPI …`; becomes a list) |
| filter | `page.ts` (the type, the label, and the misnamed `ClientKind = "npm"`) |
| scripts | `bootstrap.ts` (`ECOSYSTEMS`), `lib/gateway-rule.ts` (`traffic`, `RULE_NAME`) |

### Parsing returns candidates, anchored on shape

`parsePackageUrl` changes from `ParsedPackage | null` to `ParsedPackage[]`, where an empty list means "not a package download". Four of the six ecosystems always return zero or one element; RubyGems may return several. The filter evaluates every candidate and takes the most severe verdict (block over flag over allow), and records the candidate that decided.

Dispatch is anchored on a shape that no other ecosystem accepts, so that no URL parses as two ecosystems:

| Ecosystem | Anchor |
|---|---|
| npm | `.tgz` with a `/-/` segment (as today) |
| PyPI | `/packages/` and a wheel or sdist extension, **and not** `/@v/` |
| RubyGems | `/gems/` and `.gem` |
| Cargo | `/crates/` and `.crate` or a trailing `/download` |
| Go | `/@v/` and `.zip` |
| NuGet | `.nupkg` with a path of exactly `…/{id}/{version}/{id}.{version}.nupkg` |

A cross-ecosystem ambiguity test asserts that **no URL in the fixture corpus parses under two ecosystems**, including the Go pseudo-version case above.

### Per-ecosystem enforcement

Today `ENFORCE` is global and blocks only when exactly the string `"true"`. A new ecosystem's classification is unproven, so each one should ship observe-only: widen the rule, collect `flagged` rows from real traffic, and only then enable blocking for that ecosystem.

Proposal: a second deploy setting, `PKGGUARD_OBSERVE_ONLY`, a comma-separated list of ecosystem ids, applied by the config generator (`applyEnforce`'s sibling) exactly as `ENFORCE` is. A would-be block in a listed ecosystem is recorded `flagged`, never `blocked`, the same as the existing observe-only mode. `Decision.block` stays pure policy; whether a download stops stays `block && enforced(ecosystem)`.

### Tooling the later phases depend on

- **`bootstrap census`** (new subcommand). For each ecosystem's zip, report: record count, malware count (by the real classifier), version strings the registry's comparator rejects, names that collide under the registry's normalisation, and names that exceed the KV key limit. This makes every number in this document re-runnable, and it is the gate for each phase (see [Definition of done](#definition-of-done)). It is what would have caught the 26% NuGet gap before a download did.
- **`bootstrap --ecosystem <osv-name>`** for `download`, `generate` and `load`. Today `load` is for a fresh database and applies every migration, so it cannot add one ecosystem to a live database. The new mode is data-only (no migrations), refuses when `sync_state` already has a row for that ecosystem unless forced, and uses its own checkpoint directory.
- **`gateway-rule sync`** (new command). Today `enable` and `disable` happen to `PUT` the full desired payload, so changing the `traffic` expression is only reachable as a side effect of `enable`. An explicit `sync` writes the desired state, preserves the current `enabled` flag, and prints the drift it is correcting. The rule's name must stay stable (or `findRule` must accept both the old and the new name) so the live rule is not orphaned.
- **A log line for unparsed forwarded requests.** The Worker is only invoked for traffic the Forward rule matched, so a request no parser accepts means Gateway's classifier and ours disagree. Log it (no detection row) with the path shape but no package identifiers, and surface the count on the dashboard.

### The completeness test

A single test iterates over every id in the registry and fails if any is missing a fixture: a parse fixture, a comparator fixture, an OSV directory that round-trips through `OSV_DIR`, a label, an override pattern that accepts a real name and rejects `..` and empty segments, and a `distill` → `advisoryRow` → `advisoryFromRow` round trip. With this, adding an ecosystem without wiring a call site fails the suite instead of failing in production. It must be mutation-checked: delete one field from one ecosystem and confirm the suite fails.

### Phase 0 exit criteria

- All existing tests pass; the changed signatures are the only edits to them.
- A golden test over a corpus of URLs shows npm and PyPI parse and decide **identically** before and after.
- The completeness test exists and has been mutation-checked.
- No behaviour change is observable on the live deployment.

## Per-ecosystem designs

### Phase 1: Cargo

**Why first.** Its feed has 28 malware records, all for already-removed crates, and its comparator is free. It exercises the whole new pipeline (registry, parser, bootstrap, rule widening, live client test) at the lowest possible blast radius.

**Spike, before any code: does Gateway classify real `cargo` traffic?** On a test device behind Gateway with TLS decryption on the crates hosts:

1. Install a Rust toolchain; run `cargo fetch` for a small project, with `CARGO_HOME` pointed at an empty directory so nothing is served from cache.
2. Read the Gateway HTTP activity log for the requests. Record which URL shape the client sent, and whether `PackageInfo.Ecosystem` is populated and with what string.
3. Repeat for the other documented shape (`curl` the `.crate` URL directly).

If only the documented shape is classified and real cargo uses the other, **stop**: either widen the Forward rule's traffic selector from `pkg.ecosystem` to a host match (`http.request.host` on `static.crates.io`), which our parser then handles, or raise it with Cloudflare. Do not write the parser first.

| Item | Design |
|---|---|
| Parser | Two shapes: `/crates/{name}/{name}-{version}.crate` and `/crates/{name}/{version}/download`. Never ambiguous: the name is its own path segment. |
| Normalisation | Lowercase and `_` to `-`. |
| Comparator | `compareSemver`, unchanged. |
| OSV | Directory `crates.io`. Record IDs are `GHSA-`, `RUSTSEC-` and `MAL-`. |
| Namespace | None. |
| Override pattern | `^[a-z0-9][a-z0-9-]*$` after normalisation (crate names allow `_` and `-`; both normalise to `-`). |
| Census gate | The 12 rejected range boundaries must be reviewed by hand (see [Decisions needed](#decisions-needed)). |
| Pinned fixtures | `GHSA-6v2j-vr4h-f632` (`finch_cli_rust`): malware found **only** by the CWE rule, the Cargo equivalent of `event-stream`. A `RUSTSEC-` record as the vulnerability negative control. |

### Phase 2a: RubyGems

| Item | Design |
|---|---|
| Parser | `/gems/{name}-{version}[-{platform}].gem`. Split the stem on `-` and return **every** position `i >= 1` where token `i` matches `^\d+(\.[0-9A-Za-z]+)*$` as a candidate: name is tokens before it, version is that token, platform is the rest. |
| Normalisation | Lowercase only. Do **not** fold `-` and `_`: 23 distinct pairs exist. |
| Comparator | New: `Gem::Version`. Version is split into numeric and alphabetic runs; an alphabetic segment sorts before any number (so it is a prerelease); trailing zero segments are ignored (`1.0` equals `1`); `-` is read as `.pre.` (13 feed strings contain one). |
| Platform | Ignored for matching. An advisory applies to every platform build of a version. |
| OSV | Directory `RubyGems`. IDs `GHSA-` and `MAL-`. |
| Override pattern | `^[a-z0-9][a-z0-9._-]*$` (verify against the real name list in the census). |

Why candidates work: both failure modes resolve at the index, because only the right split names a package that exists.

- `gemxy-1778522681-1.0.0.gem` has two candidates. Name `gemxy` with version `1778522681` (and platform `1.0.0`), and name `gemxy-1778522681` with version `1.0.0`. Only the second name is in the index, and it is the malware record.
- `foo-1.13.0-x86_64-darwin-19.gem` also has two. Name `foo` with version `1.13.0` (platform `x86_64-darwin-19`), and name `foo-1.13.0-x86_64-darwin` with version `19`. Only `foo` is a real package. The other candidate misses the index and returns nothing from a live OSV query, so it costs a lookup and cannot cause a false block.

Cost: each extra candidate is a KV read, and on a miss a live OSV query. Cap the candidate count (a handful) and short-circuit on the first block.

**Differential test for the comparator.** Generate expected orderings once on a machine with Ruby (`Gem::Version` ships with it), over every distinct version string in the feed plus the neighbours of each range boundary, commit the result as a JSON fixture, and run the TypeScript comparator against it in CI. CI needs no Ruby.

**Pinned fixtures.** `MAL-2026-7711` (`gemxy-1778522681`) for the name-ambiguity case, a platform-suffixed gem for the other direction, and a `GHSA-` record with a four-part range (`3.0.4.1`).

### Phase 2b: NuGet

| Item | Design |
|---|---|
| Parser | `/v3-flatcontainer/{id}/{version}/{id}.{version}.nupkg`. Take the last three segments and verify the filename equals `{id}.{version}.nupkg`. No ambiguity: id and version are separate path segments. |
| Normalisation | Lowercase on both sides, and merge the advisories of every casing variant (33 in the feed). |
| Comparator | New: NuGet's rules: SemVer 2.0 plus the legacy four-part `Major.Minor.Patch.Revision`; missing parts are zero, so `1.0`, `1.0.0` and `1.0.0.0` are equal; prerelease labels compare **case-insensitively**; build metadata is ignored. |
| OSV | Directory `NuGet`. IDs `GHSA-` and `MAL-`. |
| Override pattern | Lowercased id: `^[a-z0-9][a-z0-9._-]*$`. |

The path version is NuGet's normalised form (a fourth zero part dropped, build metadata removed). OSV's strings are not guaranteed normalised, so compare through the comparator, never by string equality.

**Differential test.** As for RubyGems, with the oracle generated once on a machine with the .NET SDK using NuGet's own `NuGet.Versioning` comparison, committed as JSON.

**Pinned fixtures.** `MAL-2024-11505` (`Bunifu.Form`), a mixed-case name that proves the lowercase fold works end to end. `GHSA-28xm-prxc-5866` (`OpenTelemetry.Sampler.AWS`) or another record with a four-part boundary, as the regression for the 26% case.

**Unchecked.** Older NuGet clients use the v2 endpoint (`/api/v2/package/{id}/{version}`), which redirects to the flat container. Whether Gateway classifies the redirect target, and whether the first request is also classified, has not been checked. Test it in the live phase.

### Phase 3: Go

| Item | Design |
|---|---|
| Parser | `/{module}/@v/{version}.zip`. Only `.zip` is a download; `.info` and `.mod` are metadata. Module path is everything before `/@v/`, with the proxy's `!x` escape decoded to `X` (measured: `.../!burnt!sushi/toml/...` returns 200, the unescaped capital returns 404). A mirror path prefix is tolerated by skipping leading segments until one contains a dot. |
| Normalisation | None: the exact decoded module path. |
| Comparator | `compareSemver` after the `v` is handled (the library already accepts it). |
| OSV | Directory `Go`. IDs `GO-` (4,808 records), `GHSA-`, `MAL-`, one `OSV-`. |
| Namespace | The Go module path is both the name and (per Cloudflare's documentation) the namespace. Our `ParsedPackage` keeps `namespace: null` and the full path as `name`, matching OSV. |
| `distill` | Skip names whose first path element has no dot. That drops the 188 `stdlib`, 34 `toolchain` and 12 malformed entries, so the advisory counts on the dashboard describe packages that can actually be downloaded. |
| Override pattern | Path of segments `[A-Za-z0-9._~-]+`, no empty segment, no `.` or `..` segment, first segment contains a dot. Today's validators forbid `/` precisely to keep `..` out of keys, so this is a security review, not a regex edit. |

**Version shapes (measured).** OSV's Go versions carry no `v` prefix (0 of 30,953) while URLs do; 1,527 carry `+incompatible`; 1,257 are pseudo-versions. All parse under `semver`.

**Unverified, to test live.** The Go default is `GOPROXY=https://proxy.golang.org,direct`. Go falls through to the next entry on 404 and 410 for a comma, but a 403 should stop the build; if it instead falls through to `direct` (a fetch from `github.com`, which is bypassed), a block would be a no-op. Confirm what Go does on the block response.

**Pinned fixtures.** `MAL-2025-2544` (`github.com/belatedplanet/hypert`) for malware, a record with a `+incompatible` version, one with a pseudo-version, an uppercase module (`github.com/BurntSushi/toml`) through the `!` escape, and the `/packages/` pseudo-version URL as the cross-ecosystem regression.

## Cross-cutting work

### The Gateway Forward rule

- `traffic` is `pkg.ecosystem in {"npm" "pypi"}`. It becomes generated from the registry: `pkg.ecosystem in {…}` over each enabled ecosystem's `gatewayName`.
- The documented value for Cargo is `cargo` (Cloudflare's logging page lists `npm, pypi, cargo`). The strings for RubyGems, Go and NuGet are **unverified**; read them from `PackageInfo.Ecosystem` in the activity log during each ecosystem's live phase rather than assuming `rubygems`, `go`, `nuget`.
- Widening goes through `gateway-rule sync`, after the Worker and the data are in place (see [Order of operations](#order-of-operations-for-each-ecosystem)). The rule's scope and the precedence stay as they are.
- The rule's identity scope and the Do Not Inspect exemption must still cover the same people: the "two scopes, one audience" limitation in the README applies unchanged, now to more hosts.

### TLS decryption and client trust

Gateway only classifies a download when the registry host is decrypted, and a client that keeps its own trust store may refuse the inspection certificate. Cloudflare's documentation names Python, Node.js, Ruby, Rust, Java and Go as runtimes that do this.

| Ecosystem | Download hosts to include in the TLS issuer check |
|---|---|
| RubyGems | `rubygems.org` (and `index.rubygems.org` for metadata) |
| Cargo | `static.crates.io` (`index.crates.io` and `crates.io` for metadata) |
| Go | `proxy.golang.org` |
| NuGet | `api.nuget.org` (the flat container, measured); check where a v2 redirect lands |

Extend the issuer-check loop in `docs/DEMO.md` with these hosts. For each client, record in the demo documentation what must be configured for it to trust the Gateway certificate; do not assume the operating-system store is enough.

### Block responses

`clientKind` in `workers/filter/src/page.ts` decides what a blocked developer sees by User-Agent, and the only machine-readable channel today is npm's JSON `error` field. How `gem`, `cargo`, `go` and `dotnet` surface a 403 is **unknown** and must be observed behind Gateway, as it was for npm and pip, not guessed. Until then they fall into `plain`, which curl-style clients print as text. Add User-Agent patterns only with evidence, and rename the `"npm"` kind to something that describes the channel (`"json"`).

### Admin API and dashboard

Ecosystem lists, labels and name patterns come from the registry. `StatusCards` shows a list per ecosystem rather than two hard-coded lines. The advisory search, detections filter and override form take their options from the registry. Each new ecosystem gets a `sync_state` row, so refresh freshness is per ecosystem.

### Refresh Workflow

`ECOSYSTEMS` in `refresh/plan.ts` and `OSV_DIR` come from the registry. `MAX_DELTA` (20,000) is a total across ecosystems and is comfortable for monthly deltas. A new ecosystem's first run after bootstrap should be a normal delta, since the bootstrap stores the newest `modified` it saw as the high-water mark.

### Local caches (a limitation, not a fix)

The cache gap documented for npm and pip applies to every new client: a package already in a local cache is never requested and so never checked. Each client's demo note needs its own cache workaround (a throwaway `CARGO_HOME`, `GEM_HOME`, `GOMODCACHE`, `NUGET_PACKAGES`; confirm the variable names in the live phase).

## Order of operations for each ecosystem

The ordering is not cosmetic. `planRun` throws if an enabled ecosystem has no `sync_state`, which fails the whole refresh run.

1. **Merge the code with the ecosystem not yet enabled** (registry entry present, excluded from the enabled list).
2. **Bootstrap the data**: `bootstrap download --ecosystem X`, `generate`, `census`, review, then `load --remote`. Confirm `sync_state` has the row and the KV key count matches the census.
3. **Enable the ecosystem in the Worker and the refresh** (add to the enabled list), observe-only. Deploy filter and admin.
4. **Run a manual refresh** and confirm it completes with zero errors for every ecosystem.
5. **Preflight the test device**: TLS issuer on the new hosts, client trust.
6. **Widen the Forward rule** with `gateway-rule sync`. Watch the dashboard and the unparsed-request log.
7. **Live test with a real client**, following [Test environment and procedure](#test-environment-and-procedure): a harmless canary package under a block override is recorded as `flagged` (observe-only), attributed to the right user; a clean package passes; a CVE-only package is flagged.
8. **Remove the ecosystem from the observe-only list**, redeploy, and repeat the canary download to confirm the 403 and what the client prints.
9. **Document**: README ecosystem statement, the demo script and the limitations, then release.

Rollback at any step is the reverse: remove the ecosystem from the rule with `sync`, then from the enabled list. The data can stay loaded.

## Test environment and procedure

A test device behind Gateway is the only way to settle the open questions, so this plan assumes one.

### Requirements

- Enrolled in Cloudflare One with an active session, and its user inside **both** the Forward rule's scope and the Do Not Inspect exemption (the "two scopes, one audience" limitation).
- The Gateway certificate trusted by the operating system.
- The TLS issuer check passing on every host in the table under [TLS decryption and client trust](#tls-decryption-and-client-trust).
- Reach to each toolchain's installer, and a few GB free.

### Baseline of the reference device

*Measured on 2026-11-07, before any toolchain was installed:* Apple silicon, session connected and healthy. **All ten registry hosts checked** (the npm and PyPI registries, and the hosts of the four new ecosystems, including both Cargo and Go metadata hosts) already present the Gateway certificate, so no carve-out change is needed. The system Ruby fetched a gem from the RubyGems host through Gateway with **no trust configuration**. There was no Rust, Go or .NET toolchain. The installers for all three are reachable.

So Phase 1 starts at installing a toolchain, not at enrolment or exemption work.

### Isolation

Install everything under **one lab directory**, using each toolchain's user-space installer with its own home variables:

| Ecosystem | Install | Isolation variables (confirm each in the live phase) |
|---|---|---|
| Cargo | `rustup` | `RUSTUP_HOME`, `CARGO_HOME` |
| RubyGems | The system Ruby is enough for `gem fetch` | `GEM_HOME` |
| Go | The official tarball | `GOROOT`, `GOPATH`, `GOMODCACHE` |
| NuGet | The `dotnet-install` script | `DOTNET_ROOT`, `NUGET_PACKAGES` |

This keeps the device clean (nothing system-wide, and no Homebrew scattering files), gives every run an **empty cache** so the cache gap cannot hide a request, and makes teardown a single `rm -rf`. If the device belongs to someone else, tell them before installing.

### Safety

Use fetch-only commands and never build, install or run what was fetched: `cargo fetch`, `gem fetch` (not `gem install`, which can run an extension's build script), `go mod download`, `dotnet restore`.

### Canary, not malware

Because the malware is gone from the registries (see [What each ecosystem buys](#what-each-ecosystem-buys)), the live block test uses a **canary**: a small, harmless, popular package placed under a **block override** through the admin API. It exercises the whole path: Gateway, the Forward rule, the Worker, the decision, the block response and what the client prints. Real malware records are covered separately by looking up a pinned fixture's package and affected version in the index, which needs no download.

For the flag test, use a real, still-downloadable package with a known CVE, chosen by looking it up in the index first.

### Procedure, per ecosystem

| Step | Do | Produces |
|---|---|---|
| A. Classify | Fetch a clean package with the client's verbose output on, capturing the exact request URLs. Read the Gateway HTTP activity log for those requests. Needs no code and no rule change: classification is Gateway's. | The URL shape the client sends, whether Gateway classified it, and the `PackageInfo.Ecosystem` string |
| B. Trust | Note whether step A succeeded with no extra configuration. If not, record the error and the configuration that fixes it. | The per-client trust instructions for the demo notes |
| C. Observe | After the ecosystem is enabled observe-only and the rule widened, fetch the canary. | A `flagged` row attributed to the user, with a package name and version that match Gateway's logged PURL |
| D. Enforce | Enable blocking for the ecosystem and fetch the canary again. Capture stdout, stderr and the exit code. For Go, also check whether it falls through to `direct`. | The block message as the client renders it |
| E. Cache | Repeat the fetch without emptying the cache. | Confirmation of the documented cache gap for this client |

Step A for Cargo is the spike that gates Phase 1, and must also cover the second URL shape by requesting the `.crate` URL directly. For NuGet, add a direct request to the v2 endpoint to see whether the redirect is classified.

### Results to record

Fill this in as each phase runs, and move the conclusions into the demo notes and the limitations.

| Ecosystem | URL shape requested | Classified by Gateway | `PackageInfo.Ecosystem` | Trusts the certificate unaided | Client output on 403 | Falls through on 403 |
|---|---|---|---|---|---|---|
| Cargo | | | | | | n/a |
| RubyGems | | | | | | n/a |
| NuGet | | | | | | n/a |
| Go | | | | | | |

## Definition of done

Each phase is finished only when all of this is true for the ecosystem:

- The registry completeness test passes and has been mutation-checked.
- The census runs clean, or every residue (rejected versions, name collisions, over-long keys) has been reviewed and the decision recorded.
- The pinned fixtures above pass, including a fixture for each ambiguity this document names.
- The differential comparator fixture passes (RubyGems and NuGet).
- The cross-ecosystem ambiguity test passes with the new parser in the corpus.
- A real client behind Gateway: a canary package under a block override is stopped with a 403, a clean control installs, a CVE-only package is flagged and allowed, and the dashboard row is attributed to the user. The client's block message is recorded in the demo documentation.
- A real malware record is covered without downloading it: the advisory lookup (dashboard or `/api/advisories` with `ecosystem` and `version`) returns `blocked` for a pinned fixture's package and affected version.
- The full suite passes unfiltered from a clean environment, in a fresh clone, and the leak sweep over tracked files and history is clean.

## Decisions needed

| # | Decision | Recommendation |
|---|---|---|
| 1 | Go: match module paths case-sensitively | **Exact.** Go treats the case variants as different modules and OSV lists them separately; folding would merge distinct packages. A mismatched-case path would also fail a build, so exact matching leaves no practical bypass. |
| 2 | RubyGems: fold `-` and `_` | **No.** 23 distinct gems differ only by that character. |
| 3 | Cargo: fold `-` and `_` | **Yes**, together with case; crates.io treats them as one name. |
| 4 | OSV-side range boundaries that are not valid SemVer (Cargo 10, Go 68; none in malware advisories) | Review each. Prefer coercing a clearly truncated version (`0.65` to `0.65.0`) on the OSV side only, with a test, over leaving the range inert. Never coerce the version of a package being downloaded. |
| 5 | RubyGems: platform in matching | **Ignore the platform.** An advisory applies to every build of a version. |
| 6 | Per-ecosystem observe-only setting | **Yes**, as above. It lets each ecosystem collect real traffic before it can block anyone. |
| 7 | Forward rule name | **Keep it stable**, or make `findRule` accept both names. Either way, the `traffic` expression is what changes. |
| 8 | Releases | Phase 0 has no tag. Each ecosystem is a minor release (`0.x.0`), since each is a user-visible capability. |

## Risks and open questions

| Risk | Why it matters | Mitigation |
|---|---|---|
| Gateway does not classify a client's real URL shape | The Forward rule never fires; no Worker change can help | The Cargo spike first, and the same activity-log check at the start of every ecosystem |
| Gateway's ecosystem strings for RubyGems, Go and NuGet differ from the ids | A rule matching a string Gateway never emits silently matches nothing | Read `PackageInfo.Ecosystem` from the log before writing the expression |
| A client does not trust the inspection certificate | Installs fail for the user, which looks like an outage | Per-client trust preflight, recorded in the demo notes |
| Unreadable range boundary leaves a range inert | A vulnerability advisory that never flags (none in a malware advisory, measured) | The census gate, which now separates boundaries from listed versions, the differential fixtures, and the explicit `null` handling already in `match.ts` |
| Candidate explosion for RubyGems | Extra KV reads and live OSV queries | Cap the candidates; short-circuit on the first block; live queries are already negative-cached |
| False positive across a wider surface | More ecosystems, more ways to block a legitimate install | Observe-only first; the existing allow override and the `ENFORCE` kill switch both take effect in seconds |
| Mirrors that Gateway classifies by URL shape | The Worker's parser must agree with Gateway's, including for path prefixes | The unparsed-request log line is the only signal; watch it after each widening |
| Yarn and similar clients | Not tested for npm either (the host works through the npm client) | Out of scope here; list under the same caveat |

Open questions, each answered on the test device during its phase (results go in the table in [Test environment and procedure](#test-environment-and-procedure)):

- How each of `gem`, `cargo`, `go` and `dotnet` renders a 403 from Gateway.
- Whether `go` falls through to `direct` on a 403.
- Whether Gateway classifies Cargo's `/download` shape and NuGet's v2 redirect.
- The exact `pkg.ecosystem` strings for RubyGems, Go and NuGet.

## Method

All figures are from 2026-11-07 and can be reproduced; Phase 0's `bootstrap census` is meant to make this routine.

- **Feed sizes and record counts:** `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/modified_id.csv` (one line per record) and a `HEAD` on `…/{ecosystem}/all.zip`.
- **Malware, names, collisions, version shapes:** the four `all.zip` files, parsed with the repository's own malware rule (the `MAL-` prefix or CWE-506, 507, 510, 511, 912, read from record and per-package `database_specific.cwe_ids`). Collisions are counted by grouping names under each candidate normalisation.
- **Rejected versions:** every `introduced`, `fixed`, `last_affected` (excluding `"0"`) and `versions[]` string, passed through `semver.parse` from the repository's dependency.
- **OSV ecosystem strings:** a package query to `api.osv.dev` per ecosystem, with an invalid ecosystem as the negative control (it returns `invalid ecosystem`).
- **Registry URL behaviour:** `HEAD` requests to the public registries for the shapes above, including wrong-case and escaped variants.
- **Whether malware is still downloadable:** for each malware record, a metadata request only (the crates.io sparse index, the RubyGems versions API, the NuGet flat-container index, the Go proxy version list). All 28 Cargo and 21 Go records, and a random 80 each for RubyGems and NuGet. No package was downloaded.
- **The Go and PyPI mis-parse:** the existing `parsePackageUrl` run against Go proxy URLs.
- **Cloudflare's classifier and version standards:** the [Package registry security](https://developers.cloudflare.com/cloudflare-one/traffic-controls/http-policies/package-registry-security/) documentation, which lists the URL shape, namespace meaning and versioning standard for all seven ecosystems it detects.
- **Index and platform suffixes:** the RubyGems compact index, `https://index.rubygems.org/versions`.

Not measured, and so not asserted here: any client's behaviour behind Gateway, any Gateway classification of a shape other than the documented ones, and anything about Maven beyond its feed counts.

# Changelog

All notable changes to this project are documented here.
Generated from [Conventional Commits](https://www.conventionalcommits.org) with [git-cliff](https://git-cliff.org).

## [0.3.1] - 2026-11-09

### Documentation
- Say which files are published (`216ffb5`)

## [0.3.0] - 2026-11-09

### Features
- **filter:** An ecosystem can be observe-only, and every reading of a download is decided (`2c3ae35`)
- **bootstrap:** A census of a feed, and loading one ecosystem at a time (`03c9095`)
- **gateway-rule:** Sync writes the desired rule and never changes whether it is enabled (`5fe3564`)
- **core:** Cargo is a defined ecosystem, not yet an enabled one (`0779309`)
- Enable Cargo (`ab745f5`)
- **core:** Define RubyGems, not yet enabled (`9999f6b`)
- Enable RubyGems (`b52c8a3`)
- **core:** Define NuGet, not yet enabled (`899baf1`)
- Enable NuGet (`e107182`)
- **core:** Define Go, not yet enabled (`d3908b5`)
- Enable Go (`227770e`)
- **filter:** Tell the go command everything on the first line (`e30411f`)
- **filter:** Report enforcement settings so the dashboard shows what is running (`b9d81e8`)
- **admin:** Tabbed dashboard with an enforcement badge, a detail sheet and a warm theme (`1a3a2d5`)

### Bug fixes
- **core:** Read the CDN shape the legacy NuGet v2 endpoint redirects to (`44f003d`)
- **filter:** Record a package's name the way the index keys it (`68eb54b`)
- **filter:** Key the go command's block message on the ecosystem, not its User-Agent (`894ee74`)

### Refactoring
- An ecosystem is a registry entry, not a ternary (`07cfd70`)

### Documentation
- Roadmap for RubyGems, Cargo, NuGet and Go (`cd1884f`)
- Roadmap test plan, and the malware is mostly already gone (`ef5556e`)
- **roadmap:** Separate unreadable range boundaries from unreadable listed versions (`5c8d563`)
- Describe the registry, observe-only ecosystems, census and sync (`5444bd9`)
- **roadmap:** Record the outcome of Phase 0 (`be9b28b`)
- **roadmap:** The Cargo spike result, and the real Gateway ecosystem strings (`2f7f92f`)
- **roadmap:** Cargo malware is not all gone, and the census numbers are final (`73122f2`)
- Cargo is live; record Phase 1, and teach the README and demo about it (`6741e6d`)
- RubyGems is live; record Phase 2a, and teach the README and demo about it (`2e1419a`)
- NuGet is live; record Phase 2b, and correct what its measurements overturned (`d83a928`)
- Go is live; README and demo for six ecosystems, and what Go's measurements showed (`a8d6826`)
- Bring AGENTS.md up to date with six ecosystems and what building them showed (`ea4dc05`)
- Describe the dashboard, the enforcement report and how to test the UI (`697e435`)
- Show the dashboard in the README (`d8ce92a`)

## [0.2.0] - 2026-11-07

### Features
- **admin:** A favicon for the dashboard (`a59ceda`)

## [0.1.2] - 2026-11-07

### Documentation
- The rule's identity scope and the Do Not Inspect exemption must match (`ce5bd27`)

## [0.1.1] - 2026-11-07

### Documentation
- A package already in a local cache is never checked (`de72d8e`)

## [0.1.0] - 2026-11-07

### Features
- **core:** OSV classifier, registry URL parsers, version matching (`a30cd84`)
- **data:** D1 schema and one-off OSV bootstrap (`45c04bb`)
- **deploy:** Generated deploy config with placeholder guard (`11bf1af`)
- **core:** KV value validation, overrides, live OSV mapping (`3bfa108`)
- **filter:** GatewayMiddleware with observe-only default (`eb16a82`)
- **infra:** Access via Terraform, Forward rule via script (`decb3d4`)
- **admin:** Access-verified API for status, detections and advisories (`ae26ae9`)
- **admin:** Kumo dashboard served through the Worker (`69300b8`)
- **admin:** Index refresh Workflow, API, schedule and dashboard panel (`d5c4960`)
- **core:** Google Chat notifier shared by both Workers (`0b2fc7a`)
- **filter:** Alert the Chat space when malware is seen (`665c73e`)
- **admin:** Overrides API and panel, and Chat notifications (`726b5e2`)
- **filter:** Rate-limit malware alerts per package and per user (`dcfe15c`)
- **core:** Block reference codes, and show them in malware alerts (`45265ca`)
- **filter:** Tell each client what it can actually show (`886e7ec`)
- **admin:** Find a block by the reference the developer quotes (`4043c0f`)
- **gateway:** Scope the Forward rule by email domain (`744a370`)
- **deploy:** Enforcement is a deploy setting, observe-only by default (`bd1bbd7`)

### Bug fixes
- **terraform:** Match the rotated service token lifetime (`795ad4a`)
- **deploy-config:** Placeholders that can't contain each other (`53f8a56`)
- **access:** One Access application for people and the service token (`5abec7d`)
- **admin:** Remove overrides with POST, not DELETE (`676bd62`)
- **filter:** Correct what is claimed about the terminal, and say why in npm's line (`db85050`)
- **bootstrap:** Apply every migration to a fresh database, not just the first (`69cd8eb`)

### Refactoring
- **gateway:** Name the Forward rule by the account convention (`0b823c8`)
- **core:** One function maps an OSV verdict to a policy outcome (`604777d`)
- **core:** One definition of how an advisory becomes a table row (`d6ba0a0`)

### Documentation
- **agents:** Document the admin Worker and its invariants (`5ed53a4`)
- **agents:** Document the refresh pipeline and its invariants (`d04863a`)
- README and a five-minute scripted demo (`4c0b1c4`)



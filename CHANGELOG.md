# Changelog

All notable changes to this project are documented here.
Generated from [Conventional Commits](https://www.conventionalcommits.org) with [git-cliff](https://git-cliff.org).

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


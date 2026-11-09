/**
 * The Gateway Forward rule, managed through the API because the Cloudflare Terraform provider
 * (5.28.x) has no `forward` action or `rule_settings.forward`. Move it into Terraform, with an
 * import, once the provider supports it.
 */

import { ECOSYSTEMS, ENABLED_ECOSYSTEMS } from "../../packages/core/src/index.js";

/**
 * Follows the account convention: <FILTER>-<Action>: <description> [<family>].
 * `findRule` matches on this name or a legacy one, so a rename needs the old name added to LEGACY_RULE_NAMES; `sync`
 * then renames the live rule in place. The name lists no ecosystem because the traffic expression below follows the
 * enabled ones.
 */
export const RULE_NAME = "HTTP-Forward: package downloads to PkgGuard [Package Registry Security]";
export const LEGACY_RULE_NAMES: readonly string[] = ["HTTP-Forward: npm and PyPI downloads to PkgGuard [Package Registry Security]"];
const isOurs = (name: string): boolean => name === RULE_NAME || LEGACY_RULE_NAMES.includes(name);
export const WORKER_NAME = "pkgguard-filter";
export const DEFAULT_PRECEDENCE = 47_000;
/** The static pkg.* demo policies run up to 46500 and must keep winning. */
export const MIN_PRECEDENCE = 46_501;

const EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
/** Lowercase labels of letters, digits and inner hyphens, at least two of them. Nothing here is a regex metacharacter except the dot. */
const DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
const WORKER_ID = /^[0-9a-f]{32}$/;

/** Whose traffic the rule applies to: these exact addresses, and everyone at these domains. */
export interface Scope {
  emails: readonly string[];
  domains: readonly string[];
}

export interface RuleInput {
  workerId: string;
  scope: Scope;
  precedence: number;
  enabled: boolean;
}

export interface RulePayload {
  name: string;
  description: string;
  enabled: boolean;
  precedence: number;
  action: "forward";
  filters: ["http"];
  traffic: string;
  identity: string;
  rule_settings: { forward: { worker_id: string } };
}

export interface GatewayRule extends RulePayload {
  id: string;
}

/**
 * Entries are an email address, or `@domain.tld` for everyone at that domain. The rule is never unscoped: an empty
 * value is an error, so a blank variable can never expose a whole tenant by accident.
 */
export function parseScope(raw: string): Scope {
  const entries = raw
    .split(",")
    .map((e) => e.trim())
    .filter((e) => e !== "");
  if (entries.length === 0) throw new Error("PKGGUARD_SCOPE must list at least one email or @domain: the rule is never unscoped");
  const emails: string[] = [];
  const domains: string[] = [];
  for (const entry of entries) {
    if (entry.startsWith("@")) {
      const domain = entry.slice(1).toLowerCase();
      if (!DOMAIN.test(domain)) throw new Error(`PKGGUARD_SCOPE has an invalid entry: ${JSON.stringify(entry)}`);
      domains.push(domain);
    } else {
      if (!EMAIL.test(entry)) throw new Error(`PKGGUARD_SCOPE has an invalid entry: ${JSON.stringify(entry)}`);
      emails.push(entry.toLowerCase());
    }
  }
  return { emails: [...new Set(emails)].sort(), domains: [...new Set(domains)].sort() };
}

/**
 * Renders the Gateway expression. A domain becomes an anchored, case-insensitive match whose local part cannot
 * contain `@`, so `x@evil.example.com` and `a@b@example.com` do not match. Dots are written `[.]`, not `\\.`, so no
 * backslash has to survive Gateway's string parsing. Everything is validated again here, so nothing can break out of
 * a quoted string even when this is called directly.
 */
export function identityExpression(scope: Scope): string {
  if (scope.emails.length === 0 && scope.domains.length === 0) throw new Error("identity expression needs at least one email or domain");
  for (const email of scope.emails) if (!EMAIL.test(email)) throw new Error(`invalid email ${JSON.stringify(email)}`);
  for (const domain of scope.domains) if (!DOMAIN.test(domain)) throw new Error(`invalid domain ${JSON.stringify(domain)}`);
  const clauses: string[] = [];
  if (scope.emails.length > 0) clauses.push(`identity.email in {${scope.emails.map((e) => `"${e}"`).join(" ")}}`);
  for (const domain of scope.domains) clauses.push(`identity.email matches "(?i)^[^@]+@${domain.replace(/\./g, "[.]")}$"`);
  return clauses.join(" or ");
}

export function buildPayload(input: RuleInput): RulePayload {
  if (!WORKER_ID.test(input.workerId)) throw new Error("workerId must be the 32-character lowercase hex Worker ID, not its name");
  if (!Number.isInteger(input.precedence) || input.precedence < MIN_PRECEDENCE) {
    throw new Error(`precedence must be an integer >= ${MIN_PRECEDENCE} so the static pkg.* policies keep winning`);
  }
  return {
    name: RULE_NAME,
    description: "Managed by scripts/gateway-rule.ts in the pkgguard repository. Do not edit in the dashboard.",
    enabled: input.enabled,
    precedence: input.precedence,
    action: "forward",
    filters: ["http"],
    traffic: trafficExpression(),
    identity: identityExpression(input.scope),
    rule_settings: { forward: { worker_id: input.workerId } },
  };
}

/** The ecosystems the rule forwards, written as Gateway's `pkg.ecosystem` selector expects. */
export const trafficExpression = (): string => `pkg.ecosystem in {${ENABLED_ECOSYSTEMS.map((id) => `"${ECOSYSTEMS[id].gatewayName}"`).join(" ")}}`;

export const findRule = (rules: readonly GatewayRule[]): GatewayRule | undefined => rules.find((r) => r.name === RULE_NAME) ?? rules.find((r) => isOurs(r.name));

export function findWorkerId(workers: ReadonlyArray<{ id: string; name: string }>): string {
  const worker = workers.find((w) => w.name === WORKER_NAME);
  if (!worker) throw new Error(`Worker "${WORKER_NAME}" not found. Deploy it first: npm run deploy:filter`);
  if (!WORKER_ID.test(worker.id)) throw new Error(`Worker "${WORKER_NAME}" has an unexpected ID format`);
  return worker.id;
}

/** Refuses a precedence another rule already holds. */
export function assertPrecedenceFree(rules: readonly GatewayRule[], precedence: number): void {
  const holder = rules.find((r) => r.precedence === precedence && !isOurs(r.name));
  if (holder) throw new Error(`precedence ${precedence} is already used by "${holder.name}"`);
}

export interface Drift {
  field: string;
  expected: unknown;
  actual: unknown;
}

/** What differs between the desired rule and the live one, so `status` can say so. */
export function diffRule(desired: RulePayload, live: GatewayRule): Drift[] {
  const out: Drift[] = [];
  const check = (field: string, expected: unknown, actual: unknown): void => {
    if (JSON.stringify(expected) !== JSON.stringify(actual)) out.push({ field, expected, actual });
  };
  check("name", desired.name, live.name);
  check("precedence", desired.precedence, live.precedence);
  check("action", desired.action, live.action);
  check("filters", desired.filters, live.filters);
  check("traffic", desired.traffic, live.traffic);
  check("identity", desired.identity, live.identity);
  check("worker_id", desired.rule_settings.forward.worker_id, live.rule_settings?.forward?.worker_id);
  return out;
}

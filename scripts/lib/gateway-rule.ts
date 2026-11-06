/**
 * The Gateway Forward rule, managed through the API because the Cloudflare Terraform provider
 * (5.28.x) has no `forward` action or `rule_settings.forward`. Move it into Terraform, with an
 * import, once the provider supports it.
 */

/** Follows the account convention: <FILTER>-<Action>: <description> [<family>]. */
export const RULE_NAME = "HTTP-Forward: npm and PyPI downloads to PkgGuard [Package Registry Security]";
export const WORKER_NAME = "pkgguard-filter";
export const DEFAULT_PRECEDENCE = 47_000;
/** The static pkg.* demo policies run up to 46500 and must keep winning. */
export const MIN_PRECEDENCE = 46_501;

const EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/;
const WORKER_ID = /^[0-9a-f]{32}$/;

export interface RuleInput {
  workerId: string;
  emails: readonly string[];
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

export function parseEmails(raw: string): string[] {
  const emails = raw
    .split(",")
    .map((e) => e.trim())
    .filter((e) => e !== "");
  if (emails.length === 0) throw new Error("PKGGUARD_DEMO_EMAILS must list at least one email: the rule is never unscoped");
  const bad = emails.filter((e) => !EMAIL.test(e));
  if (bad.length > 0) throw new Error(`PKGGUARD_DEMO_EMAILS has an invalid entry: ${JSON.stringify(bad[0])}`);
  return [...new Set(emails.map((e) => e.toLowerCase()))].sort();
}

/** Renders `identity.email in {"a@x" "b@y"}`. Emails are validated first, so nothing can break out of a quoted string. */
export function identityExpression(emails: readonly string[]): string {
  if (emails.length === 0) throw new Error("identity expression needs at least one email");
  for (const email of emails) if (!EMAIL.test(email)) throw new Error(`invalid email ${JSON.stringify(email)}`);
  return `identity.email in {${emails.map((e) => `"${e}"`).join(" ")}}`;
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
    traffic: 'pkg.ecosystem in {"npm" "pypi"}',
    identity: identityExpression(input.emails),
    rule_settings: { forward: { worker_id: input.workerId } },
  };
}

export const findRule = (rules: readonly GatewayRule[]): GatewayRule | undefined => rules.find((r) => r.name === RULE_NAME);

export function findWorkerId(workers: ReadonlyArray<{ id: string; name: string }>): string {
  const worker = workers.find((w) => w.name === WORKER_NAME);
  if (!worker) throw new Error(`Worker "${WORKER_NAME}" not found. Deploy it first: npm run deploy:filter`);
  if (!WORKER_ID.test(worker.id)) throw new Error(`Worker "${WORKER_NAME}" has an unexpected ID format`);
  return worker.id;
}

/** Refuses a precedence another rule already holds. */
export function assertPrecedenceFree(rules: readonly GatewayRule[], precedence: number): void {
  const holder = rules.find((r) => r.precedence === precedence && r.name !== RULE_NAME);
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
  check("precedence", desired.precedence, live.precedence);
  check("action", desired.action, live.action);
  check("filters", desired.filters, live.filters);
  check("traffic", desired.traffic, live.traffic);
  check("identity", desired.identity, live.identity);
  check("worker_id", desired.rule_settings.forward.worker_id, live.rule_settings?.forward?.worker_id);
  return out;
}

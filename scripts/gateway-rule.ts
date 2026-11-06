/**
 * Manages the PkgGuard Gateway Forward rule.
 *   tsx scripts/gateway-rule.ts <status|create|enable|disable|delete>
 *
 * `create` always makes the rule disabled. Credentials come from the environment (or .deploy.env):
 * TF_VAR_cloudflare_api_token, PKGGUARD_ACCOUNT_ID, PKGGUARD_SCOPE (emails and/or @domain entries).
 * Optional: PKGGUARD_FORWARD_PRECEDENCE (default 47000).
 */
import { pathToFileURL } from "node:url";
import { CloudflareApi } from "./lib/cloudflare-api.js";
import { loadDeployEnv } from "./lib/deploy-env.js";
import {
  DEFAULT_PRECEDENCE,
  RULE_NAME,
  assertPrecedenceFree,
  buildPayload,
  diffRule,
  findRule,
  findWorkerId,
  parseScope,
  type GatewayRule,
  type Scope,
} from "./lib/gateway-rule.js";

export const COMMANDS = ["status", "create", "enable", "disable", "delete"] as const;
export type Command = (typeof COMMANDS)[number];

export interface Config {
  scope: Scope;
  precedence: number;
}

type Api = Pick<CloudflareApi, "call">;

export async function execute(command: Command, api: Api, config: Config, log: (line: string) => void): Promise<void> {
  const rules = await api.call<GatewayRule[]>("GET", "/gateway/rules");
  const existing = findRule(rules);
  const resolveWorker = async (): Promise<string> =>
    findWorkerId(await api.call<Array<{ id: string; name: string }>>("GET", "/workers/workers"));
  const desired = async (enabled: boolean) =>
    buildPayload({ workerId: await resolveWorker(), scope: config.scope, precedence: config.precedence, enabled });

  switch (command) {
    case "status": {
      if (!existing) return log(`absent: "${RULE_NAME}" does not exist`);
      log(`present: id ${existing.id}, ${existing.enabled ? "ENABLED" : "disabled"}, precedence ${existing.precedence}`);
      const drift = diffRule(await desired(existing.enabled), existing);
      if (drift.length === 0) return log("in sync with the desired configuration");
      for (const d of drift) log(`drift in ${d.field}: expected ${JSON.stringify(d.expected)}, live ${JSON.stringify(d.actual)}`);
      return;
    }
    case "create": {
      if (existing) throw new Error(`the rule already exists (id ${existing.id}); use enable, disable or delete`);
      assertPrecedenceFree(rules, config.precedence);
      const created = await api.call<GatewayRule>("POST", "/gateway/rules", await desired(false));
      return log(`created disabled rule ${created.id} at precedence ${config.precedence}`);
    }
    case "enable":
    case "disable": {
      if (!existing) throw new Error("the rule does not exist; run create first");
      const enabled = command === "enable";
      if (existing.enabled === enabled && diffRule(await desired(enabled), existing).length === 0) {
        return log(`already ${enabled ? "enabled" : "disabled"} and in sync; nothing to do`);
      }
      assertPrecedenceFree(rules, config.precedence);
      await api.call("PUT", `/gateway/rules/${existing.id}`, await desired(enabled));
      return log(`${enabled ? "enabled" : "disabled"} rule ${existing.id}`);
    }
    case "delete": {
      if (!existing) return log("nothing to delete");
      await api.call("DELETE", `/gateway/rules/${existing.id}`);
      return log(`deleted rule ${existing.id}. Do this before deleting the Worker, or matching requests return 500.`);
    }
  }
}

export function loadConfig(env: Record<string, string>): Config {
  const raw = env["PKGGUARD_FORWARD_PRECEDENCE"];
  return {
    scope: parseScope(env["PKGGUARD_SCOPE"] ?? ""),
    precedence: raw === undefined ? DEFAULT_PRECEDENCE : Number(raw),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const command = process.argv[2] as Command;
  if (!COMMANDS.includes(command)) {
    console.error(`usage: gateway-rule <${COMMANDS.join("|")}>`);
    process.exit(2);
  }
  try {
    const required = loadDeployEnv(["TF_VAR_cloudflare_api_token", "PKGGUARD_ACCOUNT_ID", "PKGGUARD_SCOPE"]);
    const optional = process.env["PKGGUARD_FORWARD_PRECEDENCE"];
    const config = loadConfig({ ...required, ...(optional ? { PKGGUARD_FORWARD_PRECEDENCE: optional } : {}) });
    const api = new CloudflareApi(required["PKGGUARD_ACCOUNT_ID"] as string, required["TF_VAR_cloudflare_api_token"] as string);
    await execute(command, api, config, console.log);
  } catch (err) {
    console.error(`gateway-rule ${command} failed: ${(err as Error).message}`);
    process.exit(1);
  }
}

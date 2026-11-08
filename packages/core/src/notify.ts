/**
 * Google Chat notifications. Pure TypeScript: the fetch function is injected.
 *
 * An alert must never break the thing that raised it, so sendChat never throws and never logs the webhook URL,
 * which carries its own key and token.
 */

import { ecosystemLabel, type Ecosystem } from "./ecosystem-ids.js";
import { isReference } from "./reference.js";

export interface ChatMessage {
  text: string;
}

export type SendResult = "sent" | "skipped" | "failed";
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

const WEBHOOK_HOST = "chat.googleapis.com";

/** Only a Chat incoming-webhook URL is ever posted to, so a mistyped or hostile secret cannot turn this into an open proxy. */
export function isValidWebhook(raw: string | undefined): raw is string {
  if (!raw) return false;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.hostname === WEBHOOK_HOST &&
    url.port === "" &&
    url.username === "" &&
    url.password === "" &&
    /^\/v1\/spaces\/[A-Za-z0-9_-]+\/messages$/.test(url.pathname) &&
    url.searchParams.has("key") &&
    url.searchParams.has("token")
  );
}

export async function sendChat(fetchFn: FetchLike, webhook: string | undefined, message: ChatMessage, timeoutMs = 3000): Promise<SendResult> {
  if (webhook === undefined || webhook === "") return "skipped";
  if (!isValidWebhook(webhook)) {
    console.error("chat webhook is not a Google Chat incoming-webhook URL; alert not sent");
    return "failed";
  }
  try {
    const response = await fetchFn(webhook, {
      method: "POST",
      headers: { "content-type": "application/json; charset=UTF-8" },
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (response.ok) return "sent";
    console.error(`chat alert rejected: HTTP ${response.status}`);
    return "failed";
  } catch {
    console.error("chat alert could not be sent");
    return "failed";
  }
}

/**
 * Text that came from a request or a person is untrusted: a package name in a URL could be made to render as a
 * link or as formatting. Keep to a safe alphabet and a bounded length, and show it in a code span.
 */
export function safeToken(value: string | null | undefined, max = 100): string {
  const cleaned = (value ?? "").replace(/[^A-Za-z0-9._~+@/:=-]/g, "?");
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned === "" ? "?" : cleaned;
}

/** Free text from an administrator: markup characters are neutralised, not rejected. */
export function safeText(value: string | null | undefined, max = 200): string {
  const cleaned = (value ?? "").replace(/[\u0000-\u001f<>`*_~\\]/g, " ").replace(/\s+/g, " ").trim();
  return cleaned.length > max ? `${cleaned.slice(0, max)}…` : cleaned;
}

const code = (value: string): string => `\`${value}\``;
const osvLink = (id: string): string => `<https://osv.dev/vulnerability/${encodeURIComponent(safeToken(id, 64))}|${safeToken(id, 64)}>`;

export interface MalwareAlert {
  ecosystem: Ecosystem;
  name: string;
  version: string | null;
  user: string | null;
  /** True when the download was actually stopped; false when ENFORCE is off or it is an allow-override. */
  blocked: boolean;
  reason: "osv-malware" | "override";
  osvIds: string[];
  /** Ties this alert to the page the developer saw and to the detection row. */
  reference?: string | null;
}

export function malwareMessage(a: MalwareAlert): ChatMessage {
  const pkg = `${safeToken(a.name)}${a.version ? `@${safeToken(a.version, 64)}` : ""}`;
  const outcome = a.blocked ? "*blocked*" : "*observed, not blocked* (enforcement is off)";
  const lines = [
    `🚨 *Malicious package ${a.reason === "override" ? "on the block list" : "detected"}*`,
    `${code(pkg)} (${ecosystemLabel(a.ecosystem)}) — ${outcome}`,
    `User: ${code(safeToken(a.user ?? "unknown", 120))}`,
  ];
  if (isReference(a.reference)) lines.push(`Reference: ${code(a.reference)}`);
  if (a.osvIds.length > 0) {
    const shown = a.osvIds.slice(0, 5).map(osvLink).join(", ");
    lines.push(`Advisories: ${shown}${a.osvIds.length > 5 ? ` and ${a.osvIds.length - 5} more` : ""}`);
  }
  return { text: lines.join("\n") };
}

export interface RefreshAlert {
  status: "complete" | "failed";
  kind: string;
  trigger: string;
  added: number;
  updated: number;
  removed: number;
  errors: number;
  total: number;
  seconds: number | null;
  detail: string | null;
  dashboardUrl: string | null;
}

export function refreshMessage(a: RefreshAlert): ChatMessage {
  const link = a.dashboardUrl ? `\n<${a.dashboardUrl}|Open the dashboard>` : "";
  const by = `${safeToken(a.kind, 20)} run, started by ${code(safeToken(a.trigger, 80))}`;
  if (a.status === "failed") {
    return { text: `❌ *PkgGuard index refresh failed*\n${by}\n${safeText(a.detail ?? "unknown error", 300)}${link}` };
  }
  const took = a.seconds === null ? "" : ` in ${Math.max(0, Math.round(a.seconds))}s`;
  const parts = [`${a.added} added`, `${a.updated} updated`];
  if (a.removed > 0) parts.push(`${a.removed} withdrawn`);
  const retry = a.errors > 0 ? `\n⚠️ ${a.errors} records could not be fetched and will be retried on the next run.` : "";
  return { text: `✅ *PkgGuard index refreshed*\n${by}\n${parts.join(", ")} (${a.total} records${took})${retry}${link}` };
}

export interface OverrideAlert {
  action: "added" | "removed";
  mode: "block" | "allow";
  ecosystem: Ecosystem;
  name: string;
  versions: string[] | null;
  note: string | null;
  actor: string;
}

export function overrideMessage(a: OverrideAlert): ChatMessage {
  const scope = a.versions === null ? "all versions" : `versions ${a.versions.slice(0, 5).map((v) => code(safeToken(v, 40))).join(", ")}${a.versions.length > 5 ? ` and ${a.versions.length - 5} more` : ""}`;
  const verb = a.action === "added" ? "added" : "removed";
  const note = a.note ? `\nNote: ${safeText(a.note, 200)}` : "";
  return {
    text: `🔧 *${a.mode === "block" ? "Block" : "Allow"} override ${verb}*\n${code(safeToken(a.name))} (${ecosystemLabel(a.ecosystem)}), ${scope}\nBy ${code(safeToken(a.actor, 120))}${note}`,
  };
}

export const MALWARE_ALERT_TTL_SECONDS = 3600;

const NAME_BUDGET_BYTES = 220;
const USER_BUDGET_BYTES = 250;
/** Downloads with no identified user share one bucket, so unattributable traffic is still rate-limited. */
const ANONYMOUS = "~anonymous";

/** Cuts on a code point boundary so the result is valid text and no longer than `max` UTF-8 bytes. */
function clipBytes(value: string, max: number): string {
  const encoder = new TextEncoder();
  let out = "";
  let used = 0;
  for (const ch of value) {
    const size = encoder.encode(ch).length;
    if (used + size > max) break;
    out += ch;
    used += size;
  }
  return out;
}

/**
 * KV key used to send at most one malware alert per package per user per hour, so a repeated download cannot
 * flood the space while every affected person is still reported. KV limits keys to 512 bytes, not characters:
 * the two budgets plus the fixed prefix (at most 19 bytes) and separator come to 490, so the key always fits.
 */
export const malwareAlertKey = (ecosystem: string, name: string, user: string | null | undefined): string => {
  const who = user === null || user === undefined || user.trim() === "" ? ANONYMOUS : clipBytes(user.trim().toLowerCase(), USER_BUDGET_BYTES);
  return `alert:malware:${ecosystem}:${clipBytes(name.toLowerCase(), NAME_BUDGET_BYTES)}:${who}`;
};

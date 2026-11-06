import { isReference, safeText, safeToken, type ParsedPackage } from "@pkgguard/core";
import type { Decision } from "./decide.js";
import { fullName } from "./decide.js";

/**
 * What a blocked developer sees. The client decides what is worth sending:
 *
 * - The HTTP reason phrase is printed by npm and pip, so it carries the essentials (package, why, reference).
 * - npm also appends the `error` field of a JSON body to that line.
 * - pip ignores the body completely, and so does npm for plain text. curl shows it as it is.
 * - A browser gets a designed page.
 *
 * `Accept` cannot tell these apart: npm and pip both send `*\/*` on a download. The User-Agent can.
 */

export type ClientKind = "browser" | "npm" | "plain";

const PACKAGE_MANAGER_AGENT = /^(npm|pnpm|yarn|bun)\//i;
const DEFAULT_CONTACT = "the PkgGuard space in Google Chat";

export function clientKind(request: Pick<Request, "headers">): ClientKind {
  if ((request.headers.get("accept") ?? "").toLowerCase().includes("text/html")) return "browser";
  if (PACKAGE_MANAGER_AGENT.test(request.headers.get("user-agent") ?? "")) return "npm";
  return "plain";
}

const escapeHtml = (text: string): string =>
  text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);

/** HTTP status text is visible ASCII only, and a line break in it would be header injection. */
const reasonText = (text: string, max: number): string => {
  return text.replace(/[^\x20-\x7e]/g, "?").slice(0, max);
};

interface Facts {
  subject: string;
  ecosystem: "npm" | "pypi";
  ecosystemLabel: string;
  why: string;
  short: string;
  reference: string | null;
  advisories: Array<{ id: string; url: string }>;
  contact: string;
}

function facts(pkg: ParsedPackage, decision: Decision, rawReference: string | null, contact: string | undefined): Facts {
  const reference = isReference(rawReference) ? rawReference : null;
  const isOverride = decision.reason === "override";
  const subject = `${safeToken(fullName(pkg), 80)}@${safeToken(pkg.version, 40)}`;
  const advisories = decision.osvIds.slice(0, 5).map((id) => ({ id: safeToken(id, 64), url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` }));
  return {
    subject,
    ecosystem: pkg.ecosystem,
    ecosystemLabel: pkg.ecosystem === "pypi" ? "PyPI" : "npm",
    why: isOverride ? "An administrator has blocked this package." : "This version is listed as malware in the OSV database.",
    short: isOverride ? "blocked by an administrator" : "listed as malware",
    reference,
    advisories,
    contact: safeText(contact, 80) || DEFAULT_CONTACT,
  };
}

/** The line npm and pip print after the status code. Everything a developer needs has to fit here. */
export function reasonPhrase(f: Pick<Facts, "subject" | "short" | "reference">): string {
  return reasonText(`Blocked by PkgGuard: ${f.subject} is ${f.short}${f.reference ? `. Ref ${f.reference}` : ""}`, 160);
}

const NEXT_STEP = "Do not install it another way. If a build depends on it, pin a known-good version or remove the dependency.";

const helpLine = (f: Facts): string => `Need it anyway? Ask in ${f.contact}${f.reference ? ` and quote ${f.reference}` : ""}.`;

function plainBody(f: Facts): string {
  const rows: Array<[string, string]> = [
    ["Package", `${f.subject} (${f.ecosystemLabel})`],
    ["Why", f.why],
    ...f.advisories.map((a, i): [string, string] => [i === 0 ? "Advisory" : "", a.url]),
  ];
  if (f.reference) rows.push(["Reference", f.reference]);
  const width = Math.max(...rows.map(([k]) => k.length)) + 2;
  return [
    "PkgGuard blocked this download.",
    "",
    ...rows.map(([k, v]) => `  ${(k ? `${k}:` : "").padEnd(width)}${v}`),
    "",
    NEXT_STEP,
    helpLine(f),
    "",
  ].join("\n");
}

function jsonBody(f: Facts): string {
  const advisory = f.advisories[0];
  return JSON.stringify({
    error: `${advisory ? `Advisory ${advisory.url}. ` : ""}${helpLine(f)}`,
    blocked: true,
    reference: f.reference,
    package: f.subject,
    ecosystem: f.ecosystem,
    reason: f.why,
    advisories: f.advisories.map((a) => a.url),
  });
}

const SHIELD =
  '<svg viewBox="0 0 24 24" width="28" height="28" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.5 6v5.5c0 4.4 3 8.2 7.5 9.5 4.5-1.3 7.5-5.1 7.5-9.5V6L12 3Z"/><path d="m9.2 9.2 5.6 5.6m0-5.6-5.6 5.6"/></svg>';

const STYLE = `
:root{color-scheme:light dark;--bg:#14110f;--card:#1d1916;--line:#33291f;--text:#f3ece4;--muted:#a89a8b;--accent:#ff6a3d;--code:#261f1a}
@media(prefers-color-scheme:light){:root{--bg:#fbf6ef;--card:#fff;--line:#eadfce;--text:#2b2118;--muted:#7a6a58;--accent:#d9441a;--code:#f5ecdf}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.25rem;background:var(--bg);background-image:radial-gradient(var(--line) 1px,transparent 1px);background-size:22px 22px;color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:100%;max-width:38rem;background:var(--card);border:1px solid var(--line);border-top:3px solid var(--accent);border-radius:14px;padding:2rem 1.75rem;box-shadow:0 12px 40px rgba(0,0,0,.25)}
.kicker{display:flex;align-items:center;gap:.6rem;margin:0 0 1rem;color:var(--accent);font:600 .72rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase}
h1{margin:0 0 1.1rem;font-size:1.65rem;line-height:1.2;letter-spacing:-.01em}
h2{margin:1.5rem 0 .35rem;color:var(--muted);font:600 .72rem/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.12em;text-transform:uppercase}
p{margin:0}
.pkg{display:flex;flex-wrap:wrap;align-items:center;gap:.6rem;padding:.9rem 1rem;background:var(--code);border:1px solid var(--line);border-radius:10px}
.pkg code{font:600 1.15rem/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
.eco{padding:.15rem .5rem;border:1px solid var(--line);border-radius:999px;color:var(--muted);font:.72rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}
ul{margin:.6rem 0 0;padding:0;list-style:none;display:grid;gap:.45rem}
li a{display:block;padding:.55rem .8rem;border:1px solid var(--line);border-radius:8px;color:var(--text);text-decoration:none;font:.9rem/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
li a:hover,li a:focus-visible{border-color:var(--accent);outline:none}
.help{margin-top:1.75rem;padding:1rem 1.1rem;border:1px dashed var(--line);border-radius:10px}
.help strong{display:block;margin-bottom:.2rem}
.ref{display:inline-block;margin-top:.5rem;padding:.3rem .65rem;background:var(--code);border:1px solid var(--line);border-radius:6px;font:700 1.05rem/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;user-select:all}
footer{margin-top:1.5rem;color:var(--muted);font-size:.8rem}
`;

function htmlBody(f: Facts): string {
  const advisories = f.advisories.length
    ? `<h2>Advisory</h2><ul>${f.advisories.map((a) => `<li><a href="${escapeHtml(a.url)}" rel="noopener noreferrer">${escapeHtml(a.id)}</a></li>`).join("")}</ul>`
    : "";
  const reference = f.reference ? `<br><span class="ref">${escapeHtml(f.reference)}</span>` : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Download blocked: ${escapeHtml(f.subject)}</title><style>${STYLE}</style></head>
<body><main>
<p class="kicker">${SHIELD}<span>PkgGuard &middot; download blocked</span></p>
<h1>This package was blocked</h1>
<p class="pkg"><code>${escapeHtml(f.subject)}</code><span class="eco">${escapeHtml(f.ecosystemLabel)}</span></p>
<h2>Why</h2><p>${escapeHtml(f.why)}${f.short === "listed as malware" ? " This is not a warning about an outdated dependency." : ""}</p>
${advisories}
<h2>What to do</h2><p>${escapeHtml(NEXT_STEP)}</p>
<div class="help"><strong>Need it anyway?</strong>Ask in ${escapeHtml(f.contact)}${f.reference ? " and quote this reference:" : "."}${reference}</div>
<footer>Blocked by your organisation&rsquo;s package policy.</footer>
</main></body></html>`;
}

const SECURITY_HEADERS = {
  "cache-control": "no-store",
  "x-pkgguard-verdict": "blocked",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
} as const;

export function blockResponse(
  request: Pick<Request, "headers">,
  pkg: ParsedPackage,
  decision: Decision,
  reference: string | null,
  contact?: string,
): Response {
  const f = facts(pkg, decision, reference, contact);
  const kind = clientKind(request);
  const body = kind === "browser" ? htmlBody(f) : kind === "npm" ? jsonBody(f) : plainBody(f);
  const type = kind === "browser" ? "text/html; charset=utf-8" : kind === "npm" ? "application/json; charset=utf-8" : "text/plain; charset=utf-8";
  const headers: Record<string, string> = { ...SECURITY_HEADERS, "content-type": type };
  if (f.reference) headers["x-pkgguard-reference"] = f.reference;
  return new Response(body, { status: 403, statusText: reasonPhrase(f), headers });
}

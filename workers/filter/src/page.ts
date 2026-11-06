import type { ParsedPackage } from "@pkgguard/core";
import type { Decision } from "./decide.js";
import { fullName } from "./decide.js";

const escapeHtml = (text: string): string =>
  text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);

/** Inline, asset-free: the client is usually npm or pip and renders none of it. */
export function blockPage(pkg: ParsedPackage, decision: Decision): Response {
  const subject = escapeHtml(`${fullName(pkg)}@${pkg.version}`);
  const why =
    decision.reason === "override"
      ? "An administrator has blocked this package."
      : "This package version is listed as malware in the OSV database.";
  const advisories = decision.osvIds
    .map((id) => `<li><a href="https://osv.dev/vulnerability/${encodeURIComponent(id)}">${escapeHtml(id)}</a></li>`)
    .join("");

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Blocked by PkgGuard</title></head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem">
<h1>Download blocked</h1>
<p><strong>${subject}</strong> was blocked by your organisation's package policy.</p>
<p>${why}</p>
${advisories ? `<ul>${advisories}</ul>` : ""}
<p>Do not install this package. If you believe this is a mistake, contact your security team.</p>
</body></html>`;

  return new Response(html, {
    status: 403,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-pkgguard-verdict": "blocked",
    },
  });
}

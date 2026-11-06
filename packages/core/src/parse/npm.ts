import type { ParsedPackage } from "./types.js";

function decode(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * npm tarball URLs: `/{name}/-/{name}-{version}.tgz` and
 * `/@{scope}/{name}/-/{name}-{version}.tgz`. A mirror path prefix is tolerated.
 * Total: never throws, returns null for anything else.
 */
export function parseNpmUrl(url: URL): ParsedPackage | null {
  if (!url.pathname.endsWith(".tgz")) return null;
  const segments = url.pathname.split("/").map((s) => decode(s));
  if (segments.some((s) => s === null)) return null;
  const parts = segments as string[];

  const dash = parts.lastIndexOf("-");
  if (dash < 1 || dash !== parts.length - 2) return null;

  const file = parts[dash + 1];
  let name = parts[dash - 1];
  if (!file || !name) return null;

  let namespace: string | null = null;
  if (name.startsWith("@") && name.includes("/")) {
    // Encoded form: `/@scope%2fname/-/name-1.0.0.tgz`
    const slash = name.indexOf("/");
    namespace = name.slice(0, slash);
    name = name.slice(slash + 1);
  } else {
    const maybeScope = parts[dash - 2];
    if (maybeScope?.startsWith("@")) namespace = maybeScope;
  }
  if (!name || (namespace !== null && namespace.length < 2)) return null;

  const prefix = `${name}-`;
  if (!file.startsWith(prefix)) return null;
  const version = file.slice(prefix.length, -".tgz".length);
  if (!version) return null;

  return { ecosystem: "npm", namespace, name, version };
}

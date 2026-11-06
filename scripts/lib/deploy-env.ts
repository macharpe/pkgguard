import { existsSync, readFileSync } from "node:fs";

export function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [index, raw] of text.split("\n").entries()) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
    if (!match) throw new Error(`.deploy.env line ${index + 1} is malformed`);
    let value = (match[2] ?? "").trim();
    if (/^(['"]).*\1$/.test(value)) value = value.slice(1, -1);
    out[match[1] as string] = value;
  }
  return out;
}

/** Environment wins over `.deploy.env`, so CI can inject values without a file. */
export function loadDeployEnv(keys: readonly string[], file = ".deploy.env"): Record<string, string> {
  const fromFile = existsSync(file) ? parseEnvFile(readFileSync(file, "utf8")) : {};
  const out: Record<string, string> = {};
  const missing: string[] = [];
  for (const key of keys) {
    const value = process.env[key] ?? fromFile[key];
    if (value === undefined || value === "") missing.push(key);
    else out[key] = value;
  }
  if (missing.length > 0) {
    throw new Error(`Missing ${missing.join(", ")}. Copy .deploy.env.example to .deploy.env and fill it in.`);
  }
  return out;
}

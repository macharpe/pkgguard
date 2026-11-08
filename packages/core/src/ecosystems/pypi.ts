import { parsePypiUrl } from "../parse/pypi.js";
import { comparePep440 } from "../version/pep440.js";
import type { EcosystemSpec } from "./types.js";

/** PEP 503: lowercase, runs of `-`, `_`, `.` collapse to a single `-`. */
export function normalizePypiName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

export const pypi: EcosystemSpec = {
  id: "pypi",
  osvName: "PyPI",
  gatewayName: "pypi",
  purlType: "pypi",
  normalizeName: normalizePypiName,
  purlName: (name) => name.toLowerCase().replace(/[-_.]+/g, "-"),
  compare: comparePep440,
  namespaceOf: () => null,
  overrideNamePattern: /^[a-z0-9-]+$/,
  maxNameLength: 214,
  parse(url) {
    const pkg = parsePypiUrl(url);
    return pkg === null ? [] : [pkg];
  },
};

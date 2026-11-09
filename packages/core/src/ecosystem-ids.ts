/**
 * The ecosystems PkgGuard knows about, as plain data.
 *
 * This module imports nothing, so the dashboard can use it without pulling in the parsers and comparators.
 * Everything else about an ecosystem (parsing, ordering, normalisation) lives in `ecosystems/`, keyed by these ids.
 *
 * Adding an id here is a compile error everywhere a `Record<Ecosystem, …>` is built, which is the point.
 */
export const ECOSYSTEM_IDS = ["npm", "pypi", "cargo", "rubygems", "nuget"] as const;
export type Ecosystem = (typeof ECOSYSTEM_IDS)[number];

/**
 * Ecosystems that are switched on. An ecosystem can be defined above and stay out of this list until its advisory
 * data is loaded: refresh refuses to run for an enabled ecosystem that has no data, so enabling comes after loading.
 */
export const ENABLED_ECOSYSTEMS: readonly Ecosystem[] = ["npm", "pypi", "cargo", "rubygems"];

/** How an ecosystem is named to people. */
export const ECOSYSTEM_LABELS: Readonly<Record<Ecosystem, string>> = { npm: "npm", pypi: "PyPI", cargo: "Cargo", rubygems: "RubyGems", nuget: "NuGet" };

export function isEcosystem(value: unknown): value is Ecosystem {
  return typeof value === "string" && (ECOSYSTEM_IDS as readonly string[]).includes(value);
}

export function isEnabledEcosystem(value: unknown): value is Ecosystem {
  return isEcosystem(value) && ENABLED_ECOSYSTEMS.includes(value);
}

export const ecosystemLabel = (ecosystem: Ecosystem): string => ECOSYSTEM_LABELS[ecosystem];

/**
 * The enabled ids as a quoted SQL list, for `ecosystem IN (…)` clauses. They are written out rather than bound
 * because D1 allows 100 bound parameters per query and the clauses that use this already bind about 90 more.
 * The ids are constants of this file, never input, and any quote is doubled regardless.
 */
export const enabledEcosystemSqlList = (): string => ENABLED_ECOSYSTEMS.map((id) => `'${id.replaceAll("'", "''")}'`).join(",");

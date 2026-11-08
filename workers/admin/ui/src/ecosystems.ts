import { ENABLED_ECOSYSTEMS, ecosystemLabel, isEnabledEcosystem, type Ecosystem } from "@pkgguard/core/ecosystems";

export { ecosystemLabel };

/** Select items for a form that must name one ecosystem. */
export const ECOSYSTEM_ITEMS: Record<string, string> = Object.fromEntries(ENABLED_ECOSYSTEMS.map((id) => [id, ecosystemLabel(id)]));

/** Select items for a filter, where "all" is allowed. */
export const ECOSYSTEM_FILTER_ITEMS: Record<string, string> = { all: "All ecosystems", ...ECOSYSTEM_ITEMS };

export const DEFAULT_ECOSYSTEM: Ecosystem = ENABLED_ECOSYSTEMS[0] ?? "npm";

export const toEcosystem = (value: unknown): Ecosystem => (isEnabledEcosystem(value) ? value : DEFAULT_ECOSYSTEM);

/** "npm 12 · PyPI 3": the count of one advisory kind in each enabled ecosystem. */
export const ecosystemCounts = (advisories: Record<string, Record<string, number> | undefined>, kind: string, format: (n: number) => string): string =>
  ENABLED_ECOSYSTEMS.map((id) => `${ecosystemLabel(id)} ${format(advisories[id]?.[kind] ?? 0)}`).join(" · ");

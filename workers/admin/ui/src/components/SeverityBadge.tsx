import { Badge } from "@cloudflare/kumo/components/badge";
import type { SeverityBadgeView } from "../view.js";

/**
 * One compact badge. The hover text says what it is based on and how many advisories it does not cover; the badge
 * itself says "unrated" when some are missing, so the count is never only in a tooltip.
 */
export function SeverityBadge({ view }: { view: SeverityBadgeView | null }) {
  if (view === null) return null;
  return (
    <span title={view.title} className="inline-flex">
      <Badge variant={view.colour}>{view.label}</Badge>
      <span className="sr-only">. {view.title}</span>
    </span>
  );
}

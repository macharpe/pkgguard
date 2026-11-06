import { Badge } from "@cloudflare/kumo/components/badge";
import type { DetectionVerdict } from "../../../src/api-types.js";
import { verdictBadge } from "../format.js";

export function VerdictBadge({ verdict }: { verdict: DetectionVerdict }) {
  const { label, colour } = verdictBadge(verdict);
  return <Badge variant={colour}>{label}</Badge>;
}

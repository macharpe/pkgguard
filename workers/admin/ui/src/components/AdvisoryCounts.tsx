import { Surface } from "@cloudflare/kumo/components/surface";
import { Text } from "@cloudflare/kumo/components/text";
import type { ReactNode } from "react";
import type { StatusResponse } from "../../../src/api-types.js";
import { ecosystemCounts } from "../ecosystems.js";
import { formatCount, relativeTime } from "../format.js";

function Card({ title, value, children }: { title: string; value: string; children?: ReactNode }) {
  return (
    <Surface className="flex flex-col gap-1 rounded-xl border border-kumo-line p-5">
      <Text variant="secondary" size="sm">
        {title}
      </Text>
      <span className="text-3xl font-medium tracking-tight text-kumo-default">{value}</span>
      <div className="text-sm text-kumo-subtle">{children}</div>
    </Surface>
  );
}

const sum = (advisories: StatusResponse["advisories"], kind: string): number =>
  Object.values(advisories).reduce((total, byKind) => total + (byKind[kind] ?? 0), 0);

/** What the filter can match against: the advisory counts, per ecosystem, and the size of the OSV index. */
export function AdvisoryCounts({ status, now }: { status: StatusResponse; now: number }) {
  const { advisories, ecosystems } = status;
  const newest = ecosystems.map((e) => e.last_synced_at).sort().at(-1);
  return (
    <section aria-label="Advisories in the index" className="flex flex-col gap-3">
      <div>
        <Text variant="heading2" as="h2">
          Advisories in the index
        </Text>
        <Text variant="secondary" size="sm">
          What the filter can match a download against.
        </Text>
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3">
        <Card title="Malware advisories" value={formatCount(sum(advisories, "malware"))}>
          {ecosystemCounts(advisories, "malware", formatCount)}
        </Card>
        <Card title="Vulnerability advisories" value={formatCount(sum(advisories, "vulnerability"))}>
          {ecosystemCounts(advisories, "vulnerability", formatCount)}
        </Card>
        <Card title="OSV records" value={formatCount(ecosystems.reduce((n, e) => n + e.record_count, 0))}>
          {newest ? `Last synced ${relativeTime(newest, now)}` : "Never synced"}
        </Card>
      </div>
    </section>
  );
}

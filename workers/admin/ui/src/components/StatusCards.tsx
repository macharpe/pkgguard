import { Banner } from "@cloudflare/kumo/components/banner";
import { Surface } from "@cloudflare/kumo/components/surface";
import { Text } from "@cloudflare/kumo/components/text";
import type { ReactNode } from "react";
import type { StatusResponse } from "../../../src/api-types.js";
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

export function StatusCards({ status, now }: { status: StatusResponse; now: number }) {
  const { advisories, detections, ecosystems, lastRefresh } = status;
  const recent = detections.last24h;
  const newest = ecosystems.map((e) => e.last_synced_at).sort().at(-1);

  return (
    <section aria-label="Overview" className="flex flex-col gap-4">
      {lastRefresh === null ? (
        <Banner variant="secondary" title="No refresh has run yet" description="The data below is the initial bootstrap load from OSV." />
      ) : null}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card title="Malware advisories" value={formatCount(sum(advisories, "malware"))}>
          npm {formatCount(advisories["npm"]?.["malware"] ?? 0)} · PyPI {formatCount(advisories["pypi"]?.["malware"] ?? 0)}
        </Card>
        <Card title="Vulnerability advisories" value={formatCount(sum(advisories, "vulnerability"))}>
          npm {formatCount(advisories["npm"]?.["vulnerability"] ?? 0)} · PyPI {formatCount(advisories["pypi"]?.["vulnerability"] ?? 0)}
        </Card>
        <Card title="Blocked, last 24 hours" value={formatCount(recent.blocked)}>
          {formatCount(recent.flagged)} flagged · {formatCount(recent.allowed)} allowed
          {recent.error > 0 ? ` · ${formatCount(recent.error)} errors` : ""}
        </Card>
        <Card title="Index last synced" value={newest ? relativeTime(newest, now) : "never"}>
          {formatCount(ecosystems.reduce((n, e) => n + e.record_count, 0))} OSV records
        </Card>
      </div>
    </section>
  );
}

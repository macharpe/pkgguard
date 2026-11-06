import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Empty } from "@cloudflare/kumo/components/empty";
import { Loader } from "@cloudflare/kumo/components/loader";
import { Select } from "@cloudflare/kumo/components/select";
import { Table } from "@cloudflare/kumo/components/table";
import { Text } from "@cloudflare/kumo/components/text";
import { useCallback, useEffect, useState } from "react";
import type { DetectionRow, DetectionsResponse } from "../../../src/api-types.js";
import { api } from "../api.js";
import { packageLabel, relativeTime, splitIds } from "../format.js";
import { useResource } from "../useResource.js";
import { VerdictBadge } from "./VerdictBadge.js";

const VERDICTS = { all: "All verdicts", blocked: "Blocked", flagged: "Flagged", allowed: "Allowed", error: "Lookup errors" };
const ECOSYSTEMS = { all: "All ecosystems", npm: "npm", pypi: "PyPI" };

export function DetectionsFeed({ now }: { now: number }) {
  const [verdict, setVerdict] = useState("all");
  const [ecosystem, setEcosystem] = useState("all");
  const filters = { ...(verdict !== "all" ? { verdict } : {}), ...(ecosystem !== "all" ? { ecosystem } : {}) };

  // The first page refreshes on its own; older pages are appended by hand and stay put.
  const first = useResource<DetectionsResponse>((signal) => api.detections(filters, signal), [verdict, ecosystem], 15_000);
  const [older, setOlder] = useState<DetectionRow[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);

  useEffect(() => {
    setOlder([]);
    setCursor(null);
    setMoreError(null);
  }, [verdict, ecosystem]);

  const nextBefore = older.length > 0 ? cursor : (first.data?.nextBefore ?? null);

  const loadMore = useCallback(async () => {
    if (nextBefore === null) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const page = await api.detections({ ...filters, before: String(nextBefore) });
      setOlder((rows) => [...rows, ...page.items]);
      setCursor(page.nextBefore);
    } catch (err) {
      setMoreError(err instanceof Error ? err.message : "Could not load more");
    } finally {
      setLoadingMore(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nextBefore, verdict, ecosystem]);

  const rows = [...(first.data?.items ?? []), ...older.filter((o) => !first.data?.items.some((f) => f.id === o.id))];

  return (
    <section aria-label="Detections" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Text variant="heading2" as="h2">
            Detections
          </Text>
          <Text variant="secondary" size="sm">
            What the filter saw on package downloads. Refreshes every 15 seconds.
          </Text>
        </div>
        <div className="flex gap-2">
          <Select label="Verdict" value={verdict} onValueChange={(v) => setVerdict(String(v))} items={VERDICTS} size="sm" />
          <Select label="Ecosystem" value={ecosystem} onValueChange={(v) => setEcosystem(String(v))} items={ECOSYSTEMS} size="sm" />
        </div>
      </div>

      {first.error && first.error.kind !== "session" ? <Banner variant="error" title="Could not load detections" description={first.error.message} /> : null}

      {first.loading && rows.length === 0 ? (
        <div className="flex justify-center p-10">
          <Loader />
        </div>
      ) : rows.length === 0 ? (
        <Empty title="No detections yet" description="Package downloads from enrolled devices will appear here." />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-kumo-line">
          <Table>
            <Table.Header>
              <Table.Row>
                <Table.Head>When</Table.Head>
                <Table.Head>Verdict</Table.Head>
                <Table.Head>Package</Table.Head>
                <Table.Head>Advisories</Table.Head>
                <Table.Head>Source</Table.Head>
                <Table.Head>User</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {rows.map((row) => {
                const ids = splitIds(row.osv_ids);
                return (
                  <Table.Row key={row.id}>
                    <Table.Cell>
                      <time dateTime={row.ts} title={row.ts}>
                        {relativeTime(row.ts, now)}
                      </time>
                    </Table.Cell>
                    <Table.Cell>
                      <VerdictBadge verdict={row.verdict} />
                    </Table.Cell>
                    <Table.Cell>
                      <span className="font-mono text-sm">{packageLabel(row.package_name, row.version)}</span>
                      <span className="ml-2 text-xs text-kumo-subtle">{row.ecosystem === "pypi" ? "PyPI" : "npm"}</span>
                    </Table.Cell>
                    <Table.Cell>
                      {ids.length === 0 ? (
                        <span className="text-kumo-inactive">—</span>
                      ) : (
                        <span className="font-mono text-xs" title={ids.join(", ")}>
                          {ids[0]}
                          {ids.length > 1 ? ` +${ids.length - 1}` : ""}
                        </span>
                      )}
                    </Table.Cell>
                    <Table.Cell>{row.source ?? "—"}</Table.Cell>
                    <Table.Cell>
                      <span className="text-sm">{row.user_email ?? "—"}</span>
                    </Table.Cell>
                  </Table.Row>
                );
              })}
            </Table.Body>
          </Table>
        </div>
      )}

      {moreError ? <Banner variant="error" title="Could not load more" description={moreError} /> : null}
      {nextBefore !== null ? (
        <div className="flex justify-center">
          <Button variant="secondary" loading={loadingMore} onClick={() => void loadMore()}>
            Load older
          </Button>
        </div>
      ) : null}
    </section>
  );
}

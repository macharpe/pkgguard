import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Empty } from "@cloudflare/kumo/components/empty";
import { Input } from "@cloudflare/kumo/components/input";
import { Loader } from "@cloudflare/kumo/components/loader";
import { Select } from "@cloudflare/kumo/components/select";
import { Table } from "@cloudflare/kumo/components/table";
import { Tabs } from "@cloudflare/kumo/components/tabs";
import { Text } from "@cloudflare/kumo/components/text";
import { useCallback, useEffect, useState, type MouseEvent } from "react";
import type { DetectionRow, DetectionsResponse } from "../../../src/api-types.js";
import { api } from "../api.js";
import { packageLabel, referenceFilter, relativeTime, splitIds } from "../format.js";
import { useResource } from "../useResource.js";
import { ECOSYSTEM_FILTER_ITEMS, ecosystemLabel } from "../ecosystems.js";
import { VIEW_LABELS, detectionSeverityBadge, isDetectionView, viewVerdicts, type DetectionView } from "../view.js";
import { AdvisoryList } from "./AdvisoryLink.js";
import { DetectionPanel } from "./DetectionPanel.js";
import { SeverityBadge } from "./SeverityBadge.js";
import { VerdictBadge } from "./VerdictBadge.js";

const VIEW_TABS = (Object.keys(VIEW_LABELS) as DetectionView[]).map((value) => ({ value, label: VIEW_LABELS[value] }));

export interface DetectionsFeedProps {
  now: number;
  /** False while another tab is shown: the feed stays mounted, so loaded pages and filters survive, but stops polling. */
  active: boolean;
  onAddOverride: (row: DetectionRow) => void;
  onLookup: (row: DetectionRow) => void;
}

export function DetectionsFeed({ now, active, onAddOverride, onLookup }: DetectionsFeedProps) {
  const [view, setView] = useState<DetectionView>("attention");
  const [ecosystem, setEcosystem] = useState("all");
  const [referenceText, setReferenceText] = useState("");
  const [selected, setSelected] = useState<DetectionRow | null>(null);
  const reference = referenceFilter(referenceText);
  const referenceValue = reference.state === "valid" ? reference.value : "";
  const verdict = viewVerdicts(view) ?? "";
  const filters = {
    ...(verdict !== "" ? { verdict } : {}),
    ...(ecosystem !== "all" ? { ecosystem } : {}),
    ...(referenceValue !== "" ? { reference: referenceValue } : {}),
  };

  // The first page refreshes on its own; older pages are appended by hand and stay put.
  const first = useResource<DetectionsResponse>((signal) => api.detections(filters, signal), [verdict, ecosystem, referenceValue], 15_000, active);
  const [older, setOlder] = useState<DetectionRow[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);

  useEffect(() => {
    setOlder([]);
    setCursor(null);
    setMoreError(null);
  }, [verdict, ecosystem, referenceValue]);

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
  }, [nextBefore, verdict, ecosystem, referenceValue]);

  const rows = [...(first.data?.items ?? []), ...older.filter((o) => !first.data?.items.some((f) => f.id === o.id))];

  // A click on a link or button inside the row does its own thing. A click in a popover also bubbles here through the React
  // tree although it is not inside the row, so it is checked against the DOM too.
  const openRow = (row: DetectionRow) => (event: MouseEvent<HTMLElement>) => {
    const target = event.target as HTMLElement;
    if (!event.currentTarget.contains(target) || target.closest("a, button")) return;
    setSelected(row);
  };

  return (
    <section aria-label="Detections" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Text variant="heading2" as="h2">
            Detections
          </Text>
          <Text variant="secondary" size="sm">
            What the filter saw on package downloads. Refreshes every 15 seconds. Select a row for the detail.
          </Text>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <div className="w-44">
            <Input
              label="Search reference"
              size="sm"
              placeholder="PG-7Q2K4M"
              value={referenceText}
              onChange={(e) => setReferenceText(e.target.value)}
              {...(reference.state === "partial" ? { description: "Waiting for a full reference" } : {})}
            />
          </div>
          <Select label="Ecosystem" value={ecosystem} onValueChange={(v) => setEcosystem(String(v))} items={ECOSYSTEM_FILTER_ITEMS} size="sm" />
          <div role="group" aria-label="Which detections to show">
            <Tabs variant="segmented" size="sm" value={view} onValueChange={(v) => isDetectionView(v) && setView(v)} tabs={VIEW_TABS} />
          </div>
        </div>
      </div>

      {first.error && first.error.kind !== "session" ? <Banner variant="error" title="Could not load detections" description={first.error.message} /> : null}

      {first.loading && rows.length === 0 ? (
        <div className="flex justify-center p-10">
          <Loader />
        </div>
      ) : rows.length === 0 ? (
        reference.state === "valid" ? (
          <Empty title="No block with that reference" description="Check the code with the person who was blocked, or clear the filters." />
        ) : view === "attention" && ecosystem === "all" ? (
          <Empty title="Nothing needs attention" description="No blocked or flagged downloads. Choose All to see allowed downloads too." />
        ) : (
          <Empty title="No detections" description="Nothing matches these filters yet. Downloads from enrolled devices will appear here." />
        )
      ) : (
        <div className="overflow-x-auto rounded-xl border border-kumo-line">
          <Table className="min-w-[50rem]">
            <Table.Header>
              <Table.Row>
                <Table.Head>When</Table.Head>
                <Table.Head>Verdict</Table.Head>
                <Table.Head>Finding</Table.Head>
                <Table.Head>Package</Table.Head>
                <Table.Head>Advisories</Table.Head>
                <Table.Head>Reference</Table.Head>
                <Table.Head>User</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {rows.map((row) => (
                <Table.Row key={row.id} className="cursor-pointer hover:bg-kumo-tint" onClick={openRow(row)}>
                  <Table.Cell className="whitespace-nowrap">
                    <time dateTime={row.ts} title={row.ts}>
                      {relativeTime(row.ts, now)}
                    </time>
                  </Table.Cell>
                  <Table.Cell>
                    <VerdictBadge verdict={row.verdict} />
                  </Table.Cell>
                  <Table.Cell className="whitespace-nowrap">
                    {detectionSeverityBadge(row) ? <SeverityBadge view={detectionSeverityBadge(row)} /> : <span className="text-kumo-inactive">—</span>}
                  </Table.Cell>
                  <Table.Cell className="max-w-[26rem]">
                    <button
                      type="button"
                      onClick={() => setSelected(row)}
                      aria-label={`Show detail for ${packageLabel(row.package_name, row.version)}`}
                      className="cursor-pointer rounded text-left font-mono text-sm break-all text-kumo-default hover:underline focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                    >
                      {packageLabel(row.package_name, row.version)}
                    </button>
                    <span className="ml-2 text-xs whitespace-nowrap text-kumo-subtle">{ecosystemLabel(row.ecosystem)}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <AdvisoryList ids={splitIds(row.osv_ids)} />
                  </Table.Cell>
                  <Table.Cell>
                    {row.reference ? <span className="font-mono text-xs select-all">{row.reference}</span> : <span className="text-kumo-inactive">—</span>}
                  </Table.Cell>
                  <Table.Cell>
                    <span className="text-sm">{row.user_email ?? "—"}</span>
                  </Table.Cell>
                </Table.Row>
              ))}
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

      <DetectionPanel
        row={selected}
        now={now}
        onClose={() => setSelected(null)}
        onAddOverride={(row) => {
          setSelected(null);
          onAddOverride(row);
        }}
        onLookup={(row) => {
          setSelected(null);
          onLookup(row);
        }}
      />
    </section>
  );
}

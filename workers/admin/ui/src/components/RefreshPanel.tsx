import { Badge } from "@cloudflare/kumo/components/badge";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Meter } from "@cloudflare/kumo/components/meter";
import { Surface } from "@cloudflare/kumo/components/surface";
import { Table } from "@cloudflare/kumo/components/table";
import { Text } from "@cloudflare/kumo/components/text";
import { ArrowsClockwise } from "@phosphor-icons/react";
import { useCallback, useEffect, useRef, useState } from "react";
import type { RefreshRun, RefreshRunInfo } from "../../../src/api-types.js";
import { ApiError, api } from "../api.js";
import { formatCount, formatDuration, isActive, kindLabel, relativeTime, runDuration, runSummary, triggerLabel } from "../format.js";
import { useResource } from "../useResource.js";

const POLL_MS = 1000;

function StatusBadge({ status }: { status: RefreshRun["status"] }) {
  const map = { queued: ["Queued", "secondary"], running: ["Running", "info"], complete: ["Complete", "success"], failed: ["Failed", "error"] } as const;
  const [label, colour] = map[status];
  return <Badge variant={colour}>{label}</Badge>;
}

export interface RefreshPanelProps {
  now: number;
  /** False while another tab is shown. A run in progress is still followed, so the summary stays current; only the history stops polling. */
  active: boolean;
  onFinished: () => void;
  /** The run being followed, so the summary strip can show it too. */
  onRunChange: (run: RefreshRunInfo | null) => void;
}

export function RefreshPanel({ now, active, onFinished, onRunChange }: RefreshPanelProps) {
  const history = useResource((signal) => api.refreshHistory(signal), [], 30_000, active);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [run, setRun] = useState<RefreshRunInfo | null>(null);
  const onRunChangeRef = useRef(onRunChange);
  onRunChangeRef.current = onRunChange;
  useEffect(() => onRunChangeRef.current(run), [run]);
  const [starting, setStarting] = useState(false);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const finishedRef = useRef(onFinished);
  finishedRef.current = onFinished;

  // Pick up a run that is already in progress, started by someone else or by the schedule.
  const latest = history.data?.items[0] ?? null;
  useEffect(() => {
    if (activeId === null && latest && isActive(latest)) setActiveId(latest.id);
  }, [latest, activeId]);

  // Follow the active run once a second, and stop the moment it ends.
  useEffect(() => {
    if (activeId === null) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const next = await api.refreshRun(activeId, controller.signal);
        setRun(next);
        if (isActive(next)) {
          timer = setTimeout(() => void tick(), POLL_MS);
          return;
        }
        setActiveId(null);
        setMessage(
          next.status === "complete"
            ? { kind: "ok", text: `Refresh complete: ${runSummary(next)}.` }
            : { kind: "error", text: `Refresh failed: ${next.error_detail ?? "unknown error"}` },
        );
        history.reload();
        finishedRef.current();
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return;
        if (err instanceof ApiError && err.kind === "session") return;
        timer = setTimeout(() => void tick(), POLL_MS * 3); // a blip should not end the display
      }
    };
    void tick();
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId]);

  const start = useCallback(async () => {
    setStarting(true);
    setMessage(null);
    try {
      const { runId } = await api.startRefresh();
      setActiveId(runId);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409 && typeof err.body?.["runId"] === "string") {
        setActiveId(err.body["runId"]); // someone else's run: just watch it
      } else {
        setMessage({ kind: "error", text: err instanceof Error ? err.message : "Could not start the refresh" });
      }
    } finally {
      setStarting(false);
    }
  }, []);

  const running = activeId !== null;
  const total = run?.items_total ?? 0;
  const done = run?.items_done ?? 0;

  return (
    <section aria-label="Index refresh" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Text variant="heading2" as="h2">
            Index refresh
          </Text>
          <Text variant="secondary" size="sm">
            Pulls what changed in OSV and rebuilds the affected packages. Runs daily; start one by hand any time.
          </Text>
        </div>
        <Button variant="primary" icon={<ArrowsClockwise size={16} />} loading={starting} disabled={running} onClick={() => void start()}>
          {running ? "Refreshing…" : "Refresh now"}
        </Button>
      </div>

      {message ? <Banner variant={message.kind === "ok" ? "default" : "error"} title={message.text} /> : null}

      {running ? (
        <Surface className="flex flex-col gap-3 rounded-xl border border-kumo-line p-5">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <Text variant="body" bold>
              {run?.phase ?? "starting"}
            </Text>
            <Text variant="secondary" size="sm">
              {total > 0 ? `${formatCount(done)} of ${formatCount(total)} records` : "planning"}
              {run?.etaSeconds != null ? ` · about ${formatDuration(run.etaSeconds)} left` : ""}
            </Text>
          </div>
          {total > 0 ? <Meter label="Refresh progress" value={done} max={total} showValue={false} /> : <div className="h-2 animate-pulse rounded-full bg-kumo-tint" aria-hidden="true" />}
        </Surface>
      ) : null}

      {history.data && history.data.items.length > 0 ? (
        <div className="overflow-x-auto rounded-xl border border-kumo-line">
          <Table>
            <Table.Header>
              <Table.Row>
                <Table.Head>Started</Table.Head>
                <Table.Head>Type</Table.Head>
                <Table.Head>By</Table.Head>
                <Table.Head>Status</Table.Head>
                <Table.Head>Result</Table.Head>
                <Table.Head>Took</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {history.data.items.map((item) => {
                const took = runDuration(item);
                return (
                  <Table.Row key={item.id}>
                    <Table.Cell>
                      <time dateTime={item.started_at} title={item.started_at}>
                        {relativeTime(item.started_at, now)}
                      </time>
                    </Table.Cell>
                    <Table.Cell>{kindLabel(item.kind)}</Table.Cell>
                    <Table.Cell>{triggerLabel(item.trigger)}</Table.Cell>
                    <Table.Cell>
                      <StatusBadge status={item.status} />
                    </Table.Cell>
                    <Table.Cell>
                      <span className="text-sm">{runSummary(item)}</span>
                    </Table.Cell>
                    <Table.Cell>{took === null ? "—" : formatDuration(took)}</Table.Cell>
                  </Table.Row>
                );
              })}
            </Table.Body>
          </Table>
        </div>
      ) : null}
    </section>
  );
}

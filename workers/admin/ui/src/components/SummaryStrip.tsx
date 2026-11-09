import { Banner } from "@cloudflare/kumo/components/banner";
import { Surface } from "@cloudflare/kumo/components/surface";
import { Text } from "@cloudflare/kumo/components/text";
import type { ReactNode } from "react";
import type { RefreshRunInfo, StatusResponse } from "../../../src/api-types.js";
import { formatCount, relativeTime } from "../format.js";
import { enforcementView, indexView, type Tone } from "../view.js";

const DOT: Record<Tone | "info", string> = {
  success: "bg-kumo-success",
  warning: "bg-kumo-warning",
  // Unknown is a ring, not a fill: nothing is known, so nothing is filled in. (`bg-kumo-inactive` is not a class, since
  // that token is text-only; it once gave an invisible dot that still took up its space and indented the heading.)
  neutral: "border-2 border-current text-kumo-subtle",
  info: "bg-kumo-info",
};

const TILE_BORDER: Record<Tone, string> = {
  success: "border-kumo-success/40",
  warning: "border-kumo-warning/50",
  neutral: "border-kumo-line",
};

function Tile({ label, className = "", children }: { label: string; className?: string; children: ReactNode }) {
  return (
    <Surface className={`flex flex-col gap-1.5 rounded-xl border p-4 ${className}`}>
      <Text variant="secondary" size="sm">
        {label}
      </Text>
      {children}
    </Surface>
  );
}

function Dot({ tone }: { tone: Tone | "info" }) {
  return <span className={`size-2.5 shrink-0 rounded-full ${DOT[tone]}`} aria-hidden="true" />;
}

function EnforcementTile({ status, now }: { status: StatusResponse; now: number }) {
  const view = enforcementView(status.enforcement, now);
  return (
    <Tile label="Enforcement" className={TILE_BORDER[view.tone]}>
      <div className="flex items-center gap-2.5">
        <Dot tone={view.tone} />
        <span className="text-xl font-semibold tracking-tight text-kumo-default">{view.label}</span>
      </div>
      <Text variant="secondary" size="sm">
        {view.detail}
      </Text>
      {view.reportedAt ? (
        <Text variant="secondary" size="xs">
          <time dateTime={view.reportedAt} title={view.reportedAt}>
            Reported {relativeTime(view.reportedAt, now)}
          </time>
          {view.stale ? " · This report is old, so the filter may have changed since." : ""}
        </Text>
      ) : null}
    </Tile>
  );
}

function ActivityTile({ status }: { status: StatusResponse }) {
  const recent = status.detections.last24h;
  return (
    <Tile label="Last 24 hours" className="border-kumo-line">
      <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1">
        <span>
          <span className="text-3xl font-semibold tracking-tight text-kumo-danger">{formatCount(recent.blocked)}</span> <span className="text-sm text-kumo-subtle">blocked</span>
        </span>
        <span>
          <span className="text-3xl font-semibold tracking-tight text-kumo-warning">{formatCount(recent.flagged)}</span> <span className="text-sm text-kumo-subtle">flagged</span>
        </span>
        <span>
          <span className="text-3xl font-semibold tracking-tight text-kumo-default">{formatCount(recent.allowed)}</span> <span className="text-sm text-kumo-subtle">allowed</span>
        </span>
      </div>
      {recent.error > 0 ? (
        <Text variant="secondary" size="xs">
          {formatCount(recent.error)} lookup {recent.error === 1 ? "error" : "errors"}
        </Text>
      ) : null}
    </Tile>
  );
}

function IndexTile({ status, liveRun, now }: { status: StatusResponse; liveRun: RefreshRunInfo | null; now: number }) {
  const view = indexView(status, liveRun, now);
  return (
    <Tile label="Index" className="border-kumo-line">
      <div className="flex items-center gap-2.5">
        <Dot tone={view.tone} />
        <span className="text-base font-semibold text-kumo-default">{view.headline}</span>
      </div>
      <Text variant="secondary" size="sm">
        {view.detail}
      </Text>
      {view.running ? (
        view.progress === null ? (
          <div className="h-1.5 animate-pulse rounded-full bg-kumo-tint" aria-hidden="true" />
        ) : (
          <div role="progressbar" aria-label="Index refresh progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(view.progress * 100)} className="h-1.5 overflow-hidden rounded-full bg-kumo-tint">
            <div className="h-full rounded-full bg-kumo-brand transition-[width] duration-300" style={{ width: `${Math.round(view.progress * 100)}%` }} />
          </div>
        )
      ) : null}
    </Tile>
  );
}

/** What matters on every tab: is the filter enforcing, what it did today, and whether the index is current. */
export function SummaryStrip({ status, liveRun, now }: { status: StatusResponse; liveRun: RefreshRunInfo | null; now: number }) {
  return (
    <section aria-label="Summary" className="flex flex-col gap-3">
      {status.lastRefresh === null ? (
        <Banner variant="secondary" title="No refresh has run yet" description="The index is the initial bootstrap load from OSV." />
      ) : null}
      <div className="grid grid-cols-1 gap-3 min-[860px]:grid-cols-[1.1fr_1.5fr_1fr]">
        <EnforcementTile status={status} now={now} />
        <ActivityTile status={status} />
        <IndexTile status={status} liveRun={liveRun} now={now} />
      </div>
    </section>
  );
}

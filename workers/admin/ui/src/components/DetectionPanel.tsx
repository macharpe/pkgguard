import { Button } from "@cloudflare/kumo/components/button";
import { Badge } from "@cloudflare/kumo/components/badge";
import { Dialog } from "@cloudflare/kumo/components/dialog";
import { X } from "@phosphor-icons/react";
import { useRef, type ReactNode } from "react";
import type { DetectionRow } from "../../../src/api-types.js";
import { ecosystemLabel } from "../ecosystems.js";
import { packageLabel, relativeTime, splitIds } from "../format.js";
import { detectionExplanation, prefillFromDetection, sourceLabel } from "../view.js";
import { AdvisoryLink } from "./AdvisoryLink.js";
import { VerdictBadge } from "./VerdictBadge.js";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="pt-0.5 text-xs text-kumo-subtle">{label}</dt>
      <dd className="m-0 min-w-0 break-words text-sm text-kumo-default">{children}</dd>
    </>
  );
}

const dash = <span className="text-kumo-inactive">—</span>;

export interface DetectionPanelProps {
  row: DetectionRow | null;
  now: number;
  onClose: () => void;
  onAddOverride: (row: DetectionRow) => void;
  onLookup: (row: DetectionRow) => void;
}

/**
 * Everything the table leaves out, for one detection, and the way from a detection to an override. A modal sheet from
 * the right: Kumo's dialog traps focus, closes on Escape and returns focus to what opened it.
 */
export function DetectionPanel({ row, now, onClose, onAddOverride, onLookup }: DetectionPanelProps) {
  // Keep the last row while the sheet slides out, so it does not empty before it is gone.
  const lastRow = useRef<DetectionRow | null>(null);
  if (row) lastRow.current = row;
  const shown = row ?? lastRow.current;
  const ids = shown ? splitIds(shown.osv_ids) : [];
  const mode = shown ? prefillFromDetection(shown).mode : "block";

  return (
    <Dialog.Root
      open={row !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Dialog
        size="lg"
        className="top-0 right-0 left-auto flex h-full max-h-none w-full max-w-full translate-x-0 flex-col rounded-none p-0 sm:top-0 sm:w-[28rem] data-ending-style:translate-x-full data-starting-style:translate-x-full data-ending-style:scale-100 data-starting-style:scale-100"
        style={{ transitionProperty: "translate, opacity" }}
      >
        {shown ? (
          <>
            <div className="flex items-start justify-between gap-4 border-b border-kumo-line p-5">
              <div className="min-w-0">
                <Dialog.Title className="m-0 font-mono text-base font-semibold break-all">{packageLabel(shown.package_name, shown.version)}</Dialog.Title>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <VerdictBadge verdict={shown.verdict} />
                  <Badge variant="outline">{ecosystemLabel(shown.ecosystem)}</Badge>
                </div>
              </div>
              <Dialog.Close render={<Button variant="secondary" shape="square" size="sm" aria-label="Close" icon={<X size={16} />} />} />
            </div>

            <div className="flex min-h-0 flex-1 flex-col gap-5 overflow-y-auto p-5">
              <Dialog.Description className="m-0 rounded-lg bg-kumo-tint p-3 text-sm text-kumo-default">{detectionExplanation(shown)}</Dialog.Description>

              <div className="flex flex-col gap-1.5">
                <span className="text-xs text-kumo-subtle">Advisories</span>
                {ids.length === 0 ? (
                  dash
                ) : (
                  <ul className="flex flex-col gap-1">
                    {ids.map((id) => (
                      <li key={id}>
                        <AdvisoryLink id={id} />
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <dl className="m-0 grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-2.5">
                <Field label="Reference">{shown.reference ? <span className="font-mono text-xs select-all">{shown.reference}</span> : dash}</Field>
                <Field label="User">{shown.user_email ?? dash}</Field>
                <Field label="Source IP">{shown.src_ip ? <span className="font-mono text-xs">{shown.src_ip}</span> : dash}</Field>
                <Field label="Decided by">{sourceLabel(shown.source)}</Field>
                <Field label="Package URL">{shown.purl ? <span className="font-mono text-xs">{shown.purl}</span> : dash}</Field>
                <Field label="When">
                  <time dateTime={shown.ts} title={shown.ts}>
                    {relativeTime(shown.ts, now)}
                  </time>
                </Field>
              </dl>
            </div>

            <div className="flex flex-wrap justify-end gap-2 border-t border-kumo-line p-4">
              <Button variant="secondary" onClick={() => onLookup(shown)}>
                Look up package
              </Button>
              <Button variant="primary" onClick={() => onAddOverride(shown)}>
                Add {mode} override
              </Button>
            </div>
          </>
        ) : null}
      </Dialog>
    </Dialog.Root>
  );
}

import { advisoryDetail, SEVERITY_DISCLAIMER, type AdvisoryInput } from "../view.js";
import { AdvisoryLink } from "./AdvisoryLink.js";

/** One advisory with its score, version, vector and source behind a native disclosure, which the keyboard and screen readers already handle. */
export function AdvisoryDetail({ advisory }: { advisory: AdvisoryInput }) {
  const detail = advisoryDetail(advisory);
  if (detail.lines === null) return <AdvisoryLink id={detail.osvId} />;
  return (
    <details className="group text-sm">
      <summary className="flex cursor-pointer list-none items-center gap-2 rounded focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none">
        <AdvisoryLink id={detail.osvId} />
        <span className="text-xs text-kumo-subtle group-open:hidden">Score details</span>
        <span className="hidden text-xs text-kumo-subtle group-open:inline">Hide details</span>
      </summary>
      <div className="mt-1 flex flex-col gap-0.5 border-l border-kumo-line pl-3 text-xs text-kumo-subtle">
        {detail.lines.map((line) => (
          <span key={line}>{line}</span>
        ))}
        {detail.vector ? <span className="font-mono break-all">{detail.vector}</span> : null}
        {detail.source ? <span>Source: {detail.source}</span> : null}
        <span>{SEVERITY_DISCLAIMER}</span>
      </div>
    </details>
  );
}

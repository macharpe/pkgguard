import { Popover } from "@cloudflare/kumo/components/popover";
import { osvUrl } from "../format.js";

/** An advisory id, linking to its page on the OSV site. The id is encoded by `osvUrl`, so it cannot break out of the URL. */
export function AdvisoryLink({ id, className = "" }: { id: string; className?: string }) {
  return (
    <a className={`font-mono text-xs whitespace-nowrap text-kumo-link underline ${className}`} href={osvUrl(id)} target="_blank" rel="noopener noreferrer">
      {id}
    </a>
  );
}

/**
 * The first advisory as a link, and the rest behind a "+N" button that opens a list of links. A popover rather than
 * a tooltip: a link inside a tooltip cannot be reached from the keyboard.
 */
export function AdvisoryList({ ids }: { ids: readonly string[] }) {
  const [first, ...rest] = ids;
  if (first === undefined) return <span className="text-kumo-inactive">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5">
      <AdvisoryLink id={first} />
      {rest.length > 0 ? (
        <Popover.Root>
          <Popover.Trigger
            render={
              <button
                type="button"
                aria-label={`Show all ${ids.length} advisories`}
                className="cursor-pointer rounded border border-kumo-line px-1.5 text-xs text-kumo-subtle hover:bg-kumo-tint focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
              />
            }
          >
            +{rest.length}
          </Popover.Trigger>
          <Popover.Content side="bottom" align="start">
            <ul className="flex flex-col gap-1.5">
              {ids.map((id) => (
                <li key={id}>
                  <AdvisoryLink id={id} />
                </li>
              ))}
            </ul>
          </Popover.Content>
        </Popover.Root>
      ) : null}
    </span>
  );
}

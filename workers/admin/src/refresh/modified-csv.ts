import { isAtOrAfter } from "./iso.js";

export interface CsvItem {
  modified: string;
  id: string;
}

export interface CsvScan {
  /** Entries at or after `since`, in file order (newest first). */
  items: CsvItem[];
  /** Every well-formed line: the number of records OSV lists for the ecosystem. */
  total: number;
  malformed: number;
}

export class DeltaTooLarge extends Error {
  constructor(readonly count: number, readonly limit: number) {
    super(`${count} records changed, over the limit of ${limit}: run the bootstrap instead of a delta`);
  }
}

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * Streams `modified_id.csv` (`<iso8601>,<id>` per line, newest first) so the whole file is never held in memory.
 * The file is read to the end because its line count is the ecosystem's record count.
 * An id that could alter a URL path is treated as malformed, never fetched.
 */
export async function scanModifiedCsv(body: ReadableStream<Uint8Array>, since: string | null, maxItems: number): Promise<CsvScan> {
  const items: CsvItem[] = [];
  let total = 0;
  let malformed = 0;

  const line = (raw: string): void => {
    const text = raw.trim();
    if (text === "") return;
    const comma = text.indexOf(",");
    const modified = comma === -1 ? "" : text.slice(0, comma).trim();
    const id = comma === -1 ? "" : text.slice(comma + 1).trim();
    if (modified === "" || !SAFE_ID.test(id)) {
      malformed++;
      return;
    }
    total++;
    if (since === null || isAtOrAfter(modified, since)) {
      items.push({ modified, id });
      if (items.length > maxItems) throw new DeltaTooLarge(items.length, maxItems);
    }
  };

  const reader = body.pipeThrough(new TextDecoderStream()).getReader();
  let pending = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    pending += value;
    let newline = pending.indexOf("\n");
    while (newline !== -1) {
      line(pending.slice(0, newline));
      pending = pending.slice(newline + 1);
      newline = pending.indexOf("\n");
    }
  }
  line(pending);
  return { items, total, malformed };
}

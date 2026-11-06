import type { Ecosystem, OsvRecord } from "@pkgguard/core";

export const OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com";
/** OSV's directory name for each ecosystem. */
export const OSV_DIR: Record<Ecosystem, string> = { npm: "npm", pypi: "PyPI" };

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export type RecordResult =
  | { status: "ok"; record: OsvRecord }
  | { status: "missing" }
  | { status: "failed"; reason: string };

export interface FetchOptions {
  concurrency?: number;
  attempts?: number;
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

const SAFE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const retryable = (status: number): boolean => status === 429 || status >= 500;

export async function fetchRecord(fetchFn: FetchLike, ecosystem: Ecosystem, id: string, options: FetchOptions = {}): Promise<RecordResult> {
  if (!SAFE_ID.test(id)) return { status: "failed", reason: "unsafe id" };
  const attempts = options.attempts ?? 3;
  const sleep = options.sleep ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const url = `${OSV_BASE}/${OSV_DIR[ecosystem]}/${encodeURIComponent(id)}.json`;

  let reason = "unknown";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const response = await fetchFn(url, { signal: AbortSignal.timeout(options.timeoutMs ?? 15_000) });
      if (response.status === 404) return { status: "missing" };
      if (response.ok) {
        let body: unknown;
        try {
          body = await response.json();
        } catch {
          return { status: "failed", reason: "not JSON" };
        }
        const record = body as Partial<OsvRecord> | null;
        if (!record || typeof record !== "object" || record.id !== id || typeof record.modified !== "string") {
          return { status: "failed", reason: "unexpected record" };
        }
        return { status: "ok", record: record as OsvRecord };
      }
      reason = `HTTP ${response.status}`;
      if (!retryable(response.status)) return { status: "failed", reason };
    } catch {
      reason = "network error";
    }
    if (attempt < attempts) await sleep(250 * 2 ** (attempt - 1));
  }
  return { status: "failed", reason };
}

/** Results come back in input order. OSV's storage allows few simultaneous connections, hence the default of 6. */
export async function fetchRecords(
  fetchFn: FetchLike,
  items: ReadonlyArray<{ ecosystem: Ecosystem; id: string }>,
  options: FetchOptions = {},
): Promise<RecordResult[]> {
  const results: RecordResult[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      const item = items[index];
      if (item === undefined) return;
      results[index] = await fetchRecord(fetchFn, item.ecosystem, item.id, options);
    }
  };
  await Promise.all(Array.from({ length: Math.min(options.concurrency ?? 6, items.length) }, worker));
  return results;
}

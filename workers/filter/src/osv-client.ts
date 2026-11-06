import { OSV_QUERY_URL, osvQueryBody, parseOsvResponse, type Ecosystem, type OsvRecord } from "@pkgguard/core";

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Throws on timeout, network failure or a non-2xx answer. The caller decides what that means. */
export async function queryOsv(
  fetchFn: FetchLike,
  ecosystem: Ecosystem,
  name: string,
  timeoutMs: number,
): Promise<{ records: OsvRecord[]; complete: boolean }> {
  const response = await fetchFn(OSV_QUERY_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(osvQueryBody(ecosystem, name)),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`OSV answered ${response.status}`);
  return parseOsvResponse(await response.json());
}

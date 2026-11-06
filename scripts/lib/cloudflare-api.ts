export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

interface Envelope<T> {
  success: boolean;
  result: T;
  errors?: Array<{ code?: number; message?: string }>;
}

export class CloudflareApi {
  constructor(
    private readonly accountId: string,
    private readonly token: string,
    private readonly fetchFn: FetchLike = (url, init) => fetch(url, init),
  ) {}

  /** The token is never included in an error message. */
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const init: RequestInit = {
      method,
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    };
    const response = await this.fetchFn(`https://api.cloudflare.com/client/v4/accounts/${this.accountId}${path}`, init);
    let envelope: Envelope<T> | undefined;
    try {
      envelope = (await response.json()) as Envelope<T>;
    } catch {
      throw new Error(`${method} ${path} -> HTTP ${response.status} with a non-JSON body`);
    }
    if (!response.ok || !envelope.success) {
      const detail = (envelope.errors ?? []).map((e) => `${e.code ?? "?"}: ${e.message ?? "unknown"}`).join("; ");
      throw new Error(`${method} ${path} -> HTTP ${response.status}${detail ? ` (${detail})` : ""}`);
    }
    return envelope.result;
  }
}

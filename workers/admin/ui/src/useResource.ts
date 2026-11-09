import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "./api.js";

export interface Resource<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Loads once and, with `pollMs`, again on an interval, but only while the browser tab is visible and `active` is true.
 * `active` is for a panel that stays mounted while another tab is shown: it stops polling while hidden and loads once
 * as soon as it is shown again, so what the person returns to is current.
 * A failed reload keeps the last good data so the screen does not blank out.
 */
export function useResource<T>(load: (signal: AbortSignal) => Promise<T>, deps: readonly unknown[], pollMs?: number, active = true): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const loadRef = useRef(load);
  loadRef.current = load;
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((n) => n + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    loadRef
      .current(controller.signal)
      .then((value) => {
        setData(value);
        setError(null);
      })
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(err instanceof ApiError ? err : new ApiError("network", "Something went wrong"));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const wasActive = useRef(active);
  useEffect(() => {
    if (active && !wasActive.current && pollMs) setTick((n) => n + 1);
    wasActive.current = active;
  }, [active, pollMs]);

  useEffect(() => {
    if (!pollMs || !active) return;
    const id = setInterval(() => {
      if (document.visibilityState === "visible") setTick((n) => n + 1);
    }, pollMs);
    return () => clearInterval(id);
  }, [pollMs, active]);

  return { data, error, loading, reload };
}

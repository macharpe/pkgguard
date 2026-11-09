import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Tabs } from "@cloudflare/kumo/components/tabs";
import { useCallback, useEffect, useRef, useState } from "react";
import type { RefreshRunInfo } from "../../src/api-types.js";
import { api } from "./api.js";
import { AdvisoryCounts } from "./components/AdvisoryCounts.js";
import { DetectionsFeed } from "./components/DetectionsFeed.js";
import { Header } from "./components/Header.js";
import { OverridesPanel } from "./components/OverridesPanel.js";
import { PackageLookup, type LookupRequest } from "./components/PackageLookup.js";
import { RefreshPanel } from "./components/RefreshPanel.js";
import { SummaryStrip } from "./components/SummaryStrip.js";
import { useResource } from "./useResource.js";
import { TABS, TAB_LABELS, parseTabHash, prefillFromDetection, prefillFromLookup, tabHash, type OverridePrefill, type PrefillRequest, type TabId } from "./view.js";

/** One clock for the whole page, so every "5m ago" moves together. */
function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

/** The tab lives in the URL hash, so a reload or a shared link lands on the same tab. */
function useHashTab(): [TabId, (tab: TabId) => void] {
  const [tab, setTab] = useState<TabId>(() => parseTabHash(window.location.hash));
  useEffect(() => {
    const onHashChange = () => setTab(parseTabHash(window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);
  const select = useCallback((next: TabId) => {
    setTab(next);
    if (window.location.hash !== tabHash(next)) window.history.replaceState(null, "", tabHash(next));
  }, []);
  return [tab, select];
}

const TAB_ITEMS = TABS.map((value) => ({ value, label: TAB_LABELS[value] }));
const isTab = (value: string): value is TabId => (TABS as readonly string[]).includes(value);

export default function App() {
  const now = useNow();
  const [tab, selectTab] = useHashTab();
  const status = useResource((signal) => api.status(signal), [], 30_000);
  const who = useResource((signal) => api.whoami(signal), []);
  const sessionEnded = [status.error, who.error].some((e) => e?.kind === "session");

  const [liveRun, setLiveRun] = useState<RefreshRunInfo | null>(null);
  const [prefill, setPrefill] = useState<PrefillRequest | null>(null);
  const [lookup, setLookup] = useState<LookupRequest | null>(null);
  const nonce = useRef(0);

  const requestOverride = useCallback(
    (p: OverridePrefill) => {
      setPrefill({ ...p, nonce: ++nonce.current });
      selectTab("packages");
    },
    [selectTab],
  );

  return (
    <div className="min-h-screen bg-kumo-canvas text-kumo-default">
      <Header who={who.data} />
      <main className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-6">
        {sessionEnded ? (
          <Banner
            variant="alert"
            title="Your session has ended"
            description="Sign in again to keep using the dashboard."
            action={
              <Button variant="primary" size="sm" onClick={() => window.location.reload()}>
                Sign in
              </Button>
            }
          />
        ) : null}
        {status.error && status.error.kind !== "session" ? <Banner variant="error" title="Could not load the overview" description={status.error.message} /> : null}
        {/* Once the session has ended every panel would only show stale or empty data, so show none. */}
        {sessionEnded ? null : (
          <>
            {status.data ? <SummaryStrip status={status.data} liveRun={liveRun} now={now} /> : null}
            <Tabs variant="underline" value={tab} onValueChange={(v) => isTab(v) && selectTab(v)} tabs={TAB_ITEMS} />

            {/* Every tab stays mounted and is only hidden, so loaded pages, filters and a run in progress survive a switch. */}
            <div hidden={tab !== "detections"}>
              <DetectionsFeed
                now={now}
                active={tab === "detections"}
                onAddOverride={(row) => requestOverride(prefillFromDetection(row))}
                onLookup={(row) => {
                  setLookup({ name: row.package_name, version: row.version ?? "", ecosystem: row.ecosystem, nonce: ++nonce.current });
                  selectTab("packages");
                }}
              />
            </div>
            <div hidden={tab !== "packages"} className="flex flex-col gap-10">
              <PackageLookup request={lookup} onOverride={(mode, pkg, version) => requestOverride(prefillFromLookup(mode, pkg, version))} />
              <OverridesPanel now={now} prefill={prefill} onPrefillDone={() => setPrefill(null)} />
            </div>
            <div hidden={tab !== "index"} className="flex flex-col gap-10">
              {status.data ? <AdvisoryCounts status={status.data} now={now} /> : null}
              <RefreshPanel now={now} active={tab === "index"} onFinished={status.reload} onRunChange={setLiveRun} />
            </div>
          </>
        )}
      </main>
    </div>
  );
}

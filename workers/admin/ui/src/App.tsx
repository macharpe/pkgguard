import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { useEffect, useState } from "react";
import { api } from "./api.js";
import { DetectionsFeed } from "./components/DetectionsFeed.js";
import { Header } from "./components/Header.js";
import { PackageLookup } from "./components/PackageLookup.js";
import { StatusCards } from "./components/StatusCards.js";
import { useResource } from "./useResource.js";

/** One clock for the whole page, so every "5m ago" moves together. */
function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

export default function App() {
  const now = useNow();
  const status = useResource((signal) => api.status(signal), [], 30_000);
  const who = useResource((signal) => api.whoami(signal), []);
  const sessionEnded = [status.error, who.error].some((e) => e?.kind === "session");

  return (
    <div className="min-h-screen bg-kumo-canvas text-kumo-default">
      <Header who={who.data} />
      <main className="mx-auto flex max-w-6xl flex-col gap-10 px-6 py-8">
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
            {status.data ? <StatusCards status={status.data} now={now} /> : null}
            <PackageLookup />
            <DetectionsFeed now={now} />
          </>
        )}
      </main>
    </div>
  );
}

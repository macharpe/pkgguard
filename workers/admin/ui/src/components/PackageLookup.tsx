import { Badge } from "@cloudflare/kumo/components/badge";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Empty } from "@cloudflare/kumo/components/empty";
import { Input } from "@cloudflare/kumo/components/input";
import { Loader } from "@cloudflare/kumo/components/loader";
import { Select } from "@cloudflare/kumo/components/select";
import { Text } from "@cloudflare/kumo/components/text";
import { MagnifyingGlass } from "@phosphor-icons/react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import type { AdvisoriesResponse, AdvisoryRow, OverrideMode, PackageResult } from "../../../src/api-types.js";
import { api } from "../api.js";
import { ECOSYSTEM_FILTER_ITEMS, ecosystemLabel } from "../ecosystems.js";
import { plural, simulationLabel } from "../format.js";
import { AdvisoryDetail } from "./AdvisoryDetail.js";
import { SeverityBadge } from "./SeverityBadge.js";
import { VerdictBadge } from "./VerdictBadge.js";
import { advisoryBadge, lookupAdvisoryNote, severityBadge, summariseSeverity } from "../view.js";

/** A search someone else asked for, such as the detection panel's "Look up package". A new `nonce` runs it again. */
export interface LookupRequest {
  name: string;
  version: string;
  ecosystem: string;
  nonce: number;
}

function Advisories({ title, rows }: { title: string; rows: AdvisoryRow[] }) {
  if (rows.length === 0) return null;
  return (
    <div className="flex flex-col gap-1">
      <Text variant="secondary" size="xs" bold>
        {title} ({rows.length})
      </Text>
      <ul className="flex flex-col gap-1">
        {rows.slice(0, 8).map((row) => (
          <li key={row.osv_id} className="flex flex-wrap items-baseline gap-x-2 text-sm">
            <AdvisoryDetail advisory={row} />
            <SeverityBadge view={advisoryBadge(row)} />
            <span className="text-kumo-subtle">{row.summary}</span>
          </li>
        ))}
      </ul>
      {rows.length > 8 ? <Text variant="secondary" size="xs">and {rows.length - 8} more</Text> : null}
    </div>
  );
}

function Result({ pkg, version, onOverride }: { pkg: PackageResult; version: string; onOverride: (mode: OverrideMode, pkg: PackageResult) => void }) {
  return (
    <li className="flex flex-col gap-3 rounded-xl border border-kumo-line bg-kumo-base p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-base break-all text-kumo-default">{pkg.name}</span>
        <Badge variant="outline">{ecosystemLabel(pkg.ecosystem)}</Badge>
        {pkg.malware.length > 0 ? <Badge variant="error">{plural(pkg.malware.length, "malware advisory", "malware advisories")}</Badge> : null}
        {pkg.vulnerabilities.length > 0 ? <Badge variant="warning">{plural(pkg.vulnerabilities.length, "vulnerability", "vulnerabilities")}</Badge> : null}
        <SeverityBadge view={severityBadge(summariseSeverity(pkg.vulnerabilities))} />
      </div>
      {pkg.osv ? (
        <div className="flex flex-wrap items-center gap-2 rounded-lg bg-kumo-tint p-3 text-sm">
          <VerdictBadge verdict={pkg.osv.outcome} />
          <span>
            {simulationLabel(pkg.osv.outcome)} at <span className="font-mono">{pkg.osv.version}</span>
          </span>
          {pkg.osv.osvIds.length > 0 ? <span className="font-mono text-xs text-kumo-subtle">{pkg.osv.osvIds.slice(0, 3).join(", ")}</span> : null}
        </div>
      ) : null}
      {pkg.malware.length + pkg.vulnerabilities.length > 0 ? <Text variant="secondary" size="xs">{lookupAdvisoryNote(version)}</Text> : null}
      <Advisories title="Malware" rows={pkg.malware} />
      <Advisories title="Vulnerabilities" rows={pkg.vulnerabilities} />
      <div className="flex flex-wrap justify-end gap-2">
        <Button size="sm" variant="secondary-destructive" onClick={() => onOverride("block", pkg)}>
          Block…
        </Button>
        <Button size="sm" variant="secondary" onClick={() => onOverride("allow", pkg)}>
          Allow…
        </Button>
      </div>
    </li>
  );
}

type Search = { status: "idle" | "loading" | "done" | "error"; data?: AdvisoriesResponse; message?: string; searched?: string; version?: string };

export function PackageLookup({ request, onOverride }: { request: LookupRequest | null; onOverride: (mode: OverrideMode, pkg: PackageResult, version: string) => void }) {
  const [q, setQ] = useState("");
  const [version, setVersion] = useState("");
  const [ecosystem, setEcosystem] = useState("all");
  const [state, setState] = useState<Search>({ status: "idle" });
  // A search that is superseded must not overwrite the newer one when it finally answers.
  const latest = useRef(0);

  async function search(query: string, ver: string, eco: string) {
    const trimmed = query.trim();
    if (trimmed === "") return;
    const mine = ++latest.current;
    setState({ status: "loading" });
    try {
      const data = await api.advisories({ q: trimmed, ...(ver.trim() ? { version: ver.trim() } : {}), ...(eco !== "all" ? { ecosystem: eco } : {}) });
      if (mine === latest.current) setState({ status: "done", data, searched: trimmed, version: ver.trim() });
    } catch (err) {
      if (mine === latest.current) setState({ status: "error", message: err instanceof Error ? err.message : "Lookup failed" });
    }
  }

  useEffect(() => {
    if (request === null) return;
    setQ(request.name);
    setVersion(request.version);
    setEcosystem(request.ecosystem);
    void search(request.name, request.version, request.ecosystem);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [request?.nonce]);

  function submit(event: FormEvent) {
    event.preventDefault();
    void search(q, version, ecosystem);
  }

  return (
    <section aria-label="Package lookup" className="flex flex-col gap-3">
      <div>
        <Text variant="heading2" as="h2">
          Package lookup
        </Text>
        <Text variant="secondary" size="sm">
          Search the OSV index by name. Add a version to see what the filter would do with it, then block or allow it.
        </Text>
      </div>

      <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
        <div className="min-w-56 flex-1">
          <Input label="Package" placeholder="lodash, @scope/name, requests" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="w-44 shrink-0">
          <Input label="Version (optional)" placeholder="4.17.20" value={version} onChange={(e) => setVersion(e.target.value)} />
        </div>
        <div className="w-48 shrink-0">
          <Select label="Ecosystem" value={ecosystem} onValueChange={(v) => setEcosystem(String(v))} items={ECOSYSTEM_FILTER_ITEMS} className="w-full" />
        </div>
        <Button type="submit" variant="primary" icon={<MagnifyingGlass size={16} />} loading={state.status === "loading"} disabled={q.trim() === ""}>
          Search
        </Button>
      </form>

      {state.status === "error" ? <Banner variant="error" title="Lookup failed" description={state.message ?? ""} /> : null}
      {state.status === "loading" ? (
        <div className="flex justify-center p-6">
          <Loader />
        </div>
      ) : null}
      {state.status === "done" && state.data ? (
        state.data.items.length === 0 ? (
          <Empty title="No advisories found" description={`Nothing in the OSV index matches "${state.searched}".`} />
        ) : (
          <>
            <ul className="flex flex-col gap-3">
              {state.data.items.map((pkg) => (
                <Result key={`${pkg.ecosystem}:${pkg.name}`} pkg={pkg} version={state.version ?? ""} onOverride={(mode, p) => onOverride(mode, p, state.version ?? "")} />
              ))}
            </ul>
            {state.data.truncated ? <Text variant="secondary" size="sm">Showing the first matches. Narrow the search to see others.</Text> : null}
          </>
        )
      ) : null}
    </section>
  );
}

import { Badge } from "@cloudflare/kumo/components/badge";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Empty } from "@cloudflare/kumo/components/empty";
import { Input } from "@cloudflare/kumo/components/input";
import { Loader } from "@cloudflare/kumo/components/loader";
import { Select } from "@cloudflare/kumo/components/select";
import { Text } from "@cloudflare/kumo/components/text";
import { MagnifyingGlass } from "@phosphor-icons/react";
import { useState, type FormEvent } from "react";
import type { AdvisoriesResponse, AdvisoryRow, PackageResult } from "../../../src/api-types.js";
import { api } from "../api.js";
import { osvUrl, plural, simulationLabel } from "../format.js";
import { VerdictBadge } from "./VerdictBadge.js";

const ECOSYSTEMS = { all: "All ecosystems", npm: "npm", pypi: "PyPI" };

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
            <a className="font-mono text-kumo-link underline" href={osvUrl(row.osv_id)} target="_blank" rel="noopener noreferrer">
              {row.osv_id}
            </a>
            {row.severity ? <Badge variant="neutral">{row.severity}</Badge> : null}
            <span className="text-kumo-subtle">{row.summary}</span>
          </li>
        ))}
      </ul>
      {rows.length > 8 ? <Text variant="secondary" size="xs">and {rows.length - 8} more</Text> : null}
    </div>
  );
}

function Result({ pkg }: { pkg: PackageResult }) {
  return (
    <li className="flex flex-col gap-3 rounded-xl border border-kumo-line bg-kumo-base p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-base text-kumo-default">{pkg.name}</span>
        <Badge variant="outline">{pkg.ecosystem === "pypi" ? "PyPI" : "npm"}</Badge>
        {pkg.malware.length > 0 ? <Badge variant="red">{plural(pkg.malware.length, "malware advisory", "malware advisories")}</Badge> : null}
        {pkg.vulnerabilities.length > 0 ? <Badge variant="orange">{plural(pkg.vulnerabilities.length, "vulnerability", "vulnerabilities")}</Badge> : null}
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
      <Advisories title="Malware" rows={pkg.malware} />
      <Advisories title="Vulnerabilities" rows={pkg.vulnerabilities} />
    </li>
  );
}

export function PackageLookup() {
  const [q, setQ] = useState("");
  const [version, setVersion] = useState("");
  const [ecosystem, setEcosystem] = useState("all");
  const [state, setState] = useState<{ status: "idle" | "loading" | "done" | "error"; data?: AdvisoriesResponse; message?: string; searched?: string }>({ status: "idle" });

  async function submit(event: FormEvent) {
    event.preventDefault();
    const query = q.trim();
    if (query === "") return;
    setState({ status: "loading" });
    try {
      const data = await api.advisories({ q: query, ...(version.trim() ? { version: version.trim() } : {}), ...(ecosystem !== "all" ? { ecosystem } : {}) });
      setState({ status: "done", data, searched: query });
    } catch (err) {
      setState({ status: "error", message: err instanceof Error ? err.message : "Lookup failed" });
    }
  }

  return (
    <section aria-label="Package lookup" className="flex flex-col gap-3">
      <div>
        <Text variant="heading2" as="h2">
          Package lookup
        </Text>
        <Text variant="secondary" size="sm">
          Search the OSV index by name. Add a version to see what the filter would do with it.
        </Text>
      </div>

      <form onSubmit={(e) => void submit(e)} className="flex flex-wrap items-end gap-3">
        <div className="min-w-56 flex-1">
          <Input label="Package" placeholder="lodash, @scope/name, requests" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="w-44 shrink-0">
          <Input label="Version (optional)" placeholder="4.17.20" value={version} onChange={(e) => setVersion(e.target.value)} />
        </div>
        <div className="w-48 shrink-0">
          <Select label="Ecosystem" value={ecosystem} onValueChange={(v) => setEcosystem(String(v))} items={ECOSYSTEMS} className="w-full" />
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
                <Result key={`${pkg.ecosystem}:${pkg.name}`} pkg={pkg} />
              ))}
            </ul>
            {state.data.truncated ? <Text variant="secondary" size="sm">Showing the first matches. Narrow the search to see others.</Text> : null}
          </>
        )
      ) : null}
    </section>
  );
}

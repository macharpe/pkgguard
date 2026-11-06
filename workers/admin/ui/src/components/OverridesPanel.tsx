import { Badge } from "@cloudflare/kumo/components/badge";
import { Banner } from "@cloudflare/kumo/components/banner";
import { Button } from "@cloudflare/kumo/components/button";
import { Empty } from "@cloudflare/kumo/components/empty";
import { Input } from "@cloudflare/kumo/components/input";
import { Loader } from "@cloudflare/kumo/components/loader";
import { Select } from "@cloudflare/kumo/components/select";
import { Table } from "@cloudflare/kumo/components/table";
import { Text } from "@cloudflare/kumo/components/text";
import { Plus, Trash } from "@phosphor-icons/react";
import { useState, type FormEvent } from "react";
import type { AddOverrideRequest, OverrideItem } from "../../../src/api-types.js";
import { api } from "../api.js";
import { parseVersionsInput, relativeTime, versionsLabel } from "../format.js";
import { useResource } from "../useResource.js";

const MODES = { block: "Block", allow: "Allow" };
const ECOSYSTEMS = { npm: "npm", pypi: "PyPI" };
const key = (o: Pick<OverrideItem, "mode" | "ecosystem" | "package_name">) => `${o.mode}:${o.ecosystem}:${o.package_name}`;

export function OverridesPanel({ now }: { now: number }) {
  const list = useResource((signal) => api.overrides(signal), []);
  const [mode, setMode] = useState<"block" | "allow">("block");
  const [ecosystem, setEcosystem] = useState<"npm" | "pypi">("npm");
  const [name, setName] = useState("");
  const [versions, setVersions] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const [message, setMessage] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  async function add(event: FormEvent) {
    event.preventDefault();
    if (name.trim() === "") return;
    const request: AddOverrideRequest = { ecosystem, mode, name: name.trim() };
    const parsed = parseVersionsInput(versions);
    if (parsed) request.versions = parsed;
    if (note.trim() !== "") request.note = note.trim();
    setSaving(true);
    setMessage(null);
    try {
      const { created, item } = await api.addOverride(request);
      setMessage({ kind: "ok", text: `${created ? "Added" : "Updated"}: ${item.mode} ${item.package_name}. It reaches the filter within about a minute.` });
      setName("");
      setVersions("");
      setNote("");
      list.reload();
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof Error ? err.message : "Could not save the override" });
    } finally {
      setSaving(false);
    }
  }

  async function remove(item: OverrideItem) {
    setRemoving(key(item));
    setMessage(null);
    try {
      await api.removeOverride({ ecosystem: item.ecosystem, mode: item.mode, name: item.package_name });
      setMessage({ kind: "ok", text: `Removed: ${item.mode} ${item.package_name}.` });
      list.reload();
    } catch (err) {
      setMessage({ kind: "error", text: err instanceof Error ? err.message : "Could not remove the override" });
    } finally {
      setRemoving(null);
    }
  }

  const items = list.data?.items ?? [];

  return (
    <section aria-label="Overrides" className="flex flex-col gap-3">
      <div>
        <Text variant="heading2" as="h2">
          Overrides
        </Text>
        <Text variant="secondary" size="sm">
          Block a package now, or allow one that OSV flags. An allow beats a block, and both beat OSV. A change reaches the filter within about a minute.
        </Text>
      </div>

      <form onSubmit={(e) => void add(e)} className="flex flex-wrap items-end gap-3">
        <div className="w-32 shrink-0">
          <Select label="Action" value={mode} onValueChange={(v) => setMode(v === "allow" ? "allow" : "block")} items={MODES} className="w-full" />
        </div>
        <div className="w-32 shrink-0">
          <Select label="Ecosystem" value={ecosystem} onValueChange={(v) => setEcosystem(v === "pypi" ? "pypi" : "npm")} items={ECOSYSTEMS} className="w-full" />
        </div>
        <div className="min-w-48 flex-1">
          <Input label="Package" placeholder="left-pad, @scope/name" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="w-48 shrink-0">
          <Input label="Versions (blank for all)" placeholder="1.3.0, 1.3.1" value={versions} onChange={(e) => setVersions(e.target.value)} />
        </div>
        <div className="min-w-48 flex-1">
          <Input label="Note (optional)" placeholder="why" value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
        <Button type="submit" variant="primary" icon={<Plus size={16} />} loading={saving} disabled={name.trim() === ""}>
          Add
        </Button>
      </form>

      {message ? <Banner variant={message.kind === "ok" ? "default" : "error"} title={message.text} /> : null}
      {list.error && list.error.kind !== "session" ? <Banner variant="error" title="Could not load overrides" description={list.error.message} /> : null}

      {list.loading && !list.data ? (
        <div className="flex justify-center p-6">
          <Loader />
        </div>
      ) : items.length === 0 ? (
        <Empty title="No overrides" description="Everything follows the OSV index." />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-kumo-line">
          <Table>
            <Table.Header>
              <Table.Row>
                <Table.Head>Action</Table.Head>
                <Table.Head>Package</Table.Head>
                <Table.Head>Versions</Table.Head>
                <Table.Head>Note</Table.Head>
                <Table.Head>Added</Table.Head>
                <Table.Head>
                  <span className="sr-only">Remove</span>
                </Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {items.map((item) => (
                <Table.Row key={key(item)}>
                  <Table.Cell>
                    <Badge variant={item.mode === "block" ? "red" : "green"}>{item.mode === "block" ? "Block" : "Allow"}</Badge>
                  </Table.Cell>
                  <Table.Cell>
                    <span className="font-mono text-sm">{item.package_name}</span>
                    <span className="ml-2 text-xs text-kumo-subtle">{item.ecosystem === "pypi" ? "PyPI" : "npm"}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <span className="font-mono text-xs">{versionsLabel(item.versions)}</span>
                  </Table.Cell>
                  <Table.Cell>{item.note ?? <span className="text-kumo-inactive">—</span>}</Table.Cell>
                  <Table.Cell>
                    <span title={`${item.created_by}, ${item.created_at}`}>{relativeTime(item.created_at, now)}</span>
                    <span className="ml-1 text-xs text-kumo-subtle">{item.created_by.split("@")[0]}</span>
                  </Table.Cell>
                  <Table.Cell>
                    <Button
                      variant="secondary-destructive"
                      size="sm"
                      shape="square"
                      aria-label={`Remove ${item.mode} override for ${item.package_name}`}
                      loading={removing === key(item)}
                      onClick={() => void remove(item)}
                    >
                      <Trash size={14} />
                    </Button>
                  </Table.Cell>
                </Table.Row>
              ))}
            </Table.Body>
          </Table>
        </div>
      )}
    </section>
  );
}

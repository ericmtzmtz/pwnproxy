import { useEffect, useState } from "preact/hooks";
import { deleteCollectionItem, listCollectionItems } from "@/api/plugins/config/calls";
import type { CollectionResponse, CollectionSpec } from "@/api/plugins/config/types";
import { ItemEditor } from "./ItemEditor";
import { formatValue, humanize, labelFor } from "./format";

/**
 * One collection: a table with `n/max` in the header, an inline editor (see
 * `./ItemEditor`) for a new item and for each row, and a delete that asks first.
 *
 * Everything is decided by the server: the capacity comes from the response
 * (`max_items`), the create button disables itself at the cap but a `409` is
 * still shown if it arrives, and a `read_only` field is painted as text because
 * no write of it would be accepted.
 */

interface CollectionTableProps {
  plugin: string;
  spec: CollectionSpec;
  /** `false` for a token of scope `agent`: a secret cannot be written with it. */
  canWriteSecret: boolean;
  /** Bumped when another client changed this plugin; reloads from the server. */
  reloadKey: number;
}

type Editor = { kind: "create" } | { kind: "edit"; id: string } | null;

export function CollectionTable({ plugin, spec, canWriteSecret, reloadKey }: CollectionTableProps) {
  const [data, setData] = useState<CollectionResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [editor, setEditor] = useState<Editor>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  async function load(): Promise<void> {
    try {
      setData(await listCollectionItems(plugin, spec.name));
      setLoadError(null);
    } catch (error: unknown) {
      setLoadError(error instanceof Error ? error.message : String(error));
    }
  }

  useEffect(() => {
    setEditor(null);
    setConfirming(null);
    setFailure(null);
    void load();
    // `reloadKey` is the panel's "another client changed this" signal.
  }, [plugin, spec.name, reloadKey]);

  async function remove(itemId: string): Promise<void> {
    if (busy) return;
    setBusy(true);
    setFailure(null);
    try {
      await deleteCollectionItem(plugin, spec.name, itemId);
      setConfirming(null);
      window.dispatchEvent(
        new CustomEvent("pwnproxy-toast", {
          detail: { title: `${humanize(spec.name)} item deleted`, message: itemId, severity: "success" },
        }),
      );
      await load();
    } catch (error: unknown) {
      setFailure(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  const items = data?.items ?? [];
  const maxItems = data?.max_items ?? spec.max_items;
  const full = items.length >= maxItems;
  const columns = spec.item.length + 1;
  const editingItem = editor?.kind === "edit" ? items.find((row) => row.id === editor.id) : undefined;

  return (
    <fieldset class="mt-3 rounded-md border border-neutral-800 bg-neutral-950 p-3">
      <legend class="px-1 text-xs font-semibold uppercase tracking-wider text-neutral-400">
        {humanize(spec.name)}{" "}
        <span class="ml-1 font-mono text-[11px] normal-case text-neutral-500">
          {items.length}/{maxItems}
        </span>
      </legend>
      {spec.help ? <p class="max-w-prose text-[11px] text-neutral-500">{spec.help}</p> : null}

      {failure ? (
        <p role="alert" class="mt-2 rounded bg-danger-900/30 px-2 py-1 text-[11px] text-danger-300">
          {failure}
        </p>
      ) : null}

      {loadError !== null ? (
        <p role="alert" class="mt-2 rounded bg-danger-900/30 px-2 py-1 text-[11px] text-danger-300">
          {loadError}
        </p>
      ) : data === null ? (
        <p class="mt-2 text-xs text-neutral-500">Loading {humanize(spec.name).toLowerCase()}…</p>
      ) : items.length === 0 && editor === null ? (
        <p class="mt-2 rounded-md border border-dashed border-neutral-800 px-3 py-4 text-center text-xs text-neutral-500">
          No items yet.
        </p>
      ) : (
        <div class="mt-2 overflow-x-auto rounded-md border border-neutral-800">
          <table class="w-full text-xs">
            <thead>
              <tr class="border-b border-neutral-800 bg-neutral-900">
                {spec.item.map((field) => (
                  <th
                    key={field.key}
                    scope="col"
                    class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400"
                  >
                    {labelFor(field)}
                  </th>
                ))}
                <th scope="col" class="px-3 py-2 text-right font-semibold uppercase tracking-wider text-neutral-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-neutral-800">
              {items.map((item) => (
                <tr key={item.id} class="bg-neutral-950 align-top hover:bg-neutral-900/50">
                  {spec.item.map((field) => (
                    <td key={field.key} class="px-3 py-2 text-neutral-300">
                      {formatValue(item.values[field.key])}
                    </td>
                  ))}
                  <td class="px-3 py-2 text-right">
                    {confirming === item.id ? (
                      <span class="inline-flex items-center gap-2">
                        <span class="text-[11px] text-neutral-400">Delete {item.id}?</span>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void remove(item.id)}
                          class="rounded bg-danger-700 px-2 py-1 text-[11px] font-semibold text-white transition-colors hover:bg-danger-600 disabled:opacity-40"
                        >
                          Confirm
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirming(null)}
                          class="rounded border border-neutral-700 px-2 py-1 text-[11px] text-neutral-300 transition-colors hover:bg-neutral-800"
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <span class="inline-flex items-center gap-1">
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => {
                            setConfirming(null);
                            setFailure(null);
                            setEditor({ kind: "edit", id: item.id });
                          }}
                          class="rounded px-2 py-1 text-[11px] text-neutral-300 transition-colors hover:bg-neutral-800 hover:text-primary-300 disabled:opacity-40"
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => setConfirming(item.id)}
                          class="rounded px-2 py-1 text-[11px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-danger-400 disabled:opacity-40"
                        >
                          Delete
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {editor !== null ? (
                <tr class="bg-neutral-900/60">
                  <td colSpan={columns} class="px-3 py-3">
                    <ItemEditor
                      key={editor.kind === "create" ? "new" : editor.id}
                      plugin={plugin}
                      spec={spec}
                      item={editingItem}
                      canWriteSecret={canWriteSecret}
                      onSaved={() => {
                        setEditor(null);
                        void load();
                      }}
                      onCancel={() => setEditor(null)}
                    />
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      )}

      {loadError === null && data !== null ? (
        <div class="mt-2 flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={full || editor !== null || busy}
            onClick={() => {
              setFailure(null);
              setEditor({ kind: "create" });
            }}
            class="rounded-md border border-neutral-700 px-3 py-1.5 text-xs text-neutral-300 transition-colors hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            New item
          </button>
          {full ? (
            <span class="text-[11px] text-neutral-500">
              The collection is full ({maxItems} items) — delete one to make room.
            </span>
          ) : null}
        </div>
      ) : null}
    </fieldset>
  );
}

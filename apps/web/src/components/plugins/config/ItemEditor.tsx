import { useId, useState } from "preact/hooks";
import {
  PluginConfigError,
  createCollectionItem,
  updateCollectionItem,
} from "@/api/plugins/config/calls";
import type { CollectionItem, CollectionSpec } from "@/api/plugins/config/types";
import { SchemaField } from "./SchemaField";
import { bareField, humanize, rawValue } from "./format";

/**
 * The inline editor of one collection item: a new one when `item` is absent,
 * a change of the existing one otherwise.
 *
 * It starts from the server's values (a secret has none to copy, so it starts
 * empty and stays untouched unless the user types), sends only what the user
 * touched, and shows the server's `detail` next to the field a `422` names.
 * An `immutable` field is `locked` while editing (the server refuses it in a
 * `PATCH`) and is left out of the body; on the create it is a normal input.
 * The parent decides what to do after `onSaved` — this component does not know
 * how the collection is loaded.
 */

interface ItemEditorProps {
  plugin: string;
  spec: CollectionSpec;
  /** Absent means "create a new item". */
  item?: CollectionItem;
  /** `false` for a token of scope `agent`: a secret cannot be written with it. */
  canWriteSecret: boolean;
  onSaved: () => void;
  onCancel: () => void;
}

interface EditorFailure {
  message: string;
  field: string | null;
}

function initialDraft(spec: CollectionSpec, item?: CollectionItem): Record<string, unknown> {
  const draft: Record<string, unknown> = {};
  if (!item) return draft;
  for (const field of spec.item) {
    const raw = rawValue(item.values[field.key]);
    if (raw !== undefined) draft[field.key] = raw;
  }
  return draft;
}

export function ItemEditor({
  plugin,
  spec,
  item,
  canWriteSecret,
  onSaved,
  onCancel,
}: ItemEditorProps) {
  const prefix = useId();
  const [draft, setDraft] = useState<Record<string, unknown>>(() => initialDraft(spec, item));
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<EditorFailure | null>(null);

  function payload(): Record<string, unknown> {
    const values: Record<string, unknown> = {};
    for (const field of spec.item) {
      if (field.read_only) continue;
      // An immutable field travels only on the create: it is part of what the
      // item is and the server answers `422` when a `PATCH` carries it. The
      // edit form shows it (`locked`) and leaves it out of the body.
      if (item !== undefined && field.immutable) continue;
      const value = draft[field.key];
      if (value === undefined) continue;
      if (field.secret && (typeof value !== "string" || value.length === 0)) continue;
      values[field.key] = value;
    }
    return values;
  }

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setFailure(null);
    try {
      const values = payload();
      if (item) {
        await updateCollectionItem(plugin, spec.name, item.id, values);
      } else {
        await createCollectionItem(plugin, spec.name, values);
      }
      window.dispatchEvent(
        new CustomEvent("pwnproxy-toast", {
          detail: {
            title: `${humanize(spec.name)} ${item ? "item updated" : "item added"}`,
            message: item ? item.id : "The plugin stored the new item.",
            severity: "success",
          },
        }),
      );
      onSaved();
    } catch (error: unknown) {
      const field = error instanceof PluginConfigError ? error.field : null;
      setFailure({ message: error instanceof Error ? error.message : String(error), field });
      const target = bareField(field);
      if (target) requestAnimationFrame(() => document.getElementById(`${prefix}-${target}`)?.focus());
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <div class="grid gap-3 sm:grid-cols-2">
        {spec.item.map((field) => (
          <SchemaField
            key={field.key}
            spec={field}
            value={item?.values[field.key]}
            draft={draft[field.key]}
            idPrefix={prefix}
            disabled={busy || (field.secret && !canWriteSecret)}
            disabledReason={field.secret && !canWriteSecret ? "Your token cannot write secrets." : undefined}
            locked={item !== undefined && field.immutable}
            error={failure?.field && bareField(failure.field) === field.key ? failure.message : null}
            onChange={(value) => setDraft((previous) => ({ ...previous, [field.key]: value }))}
          />
        ))}
      </div>
      <div class="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="submit"
          disabled={busy}
          class="rounded-md bg-primary-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
        >
          {busy
            ? "Saving…"
            : item
              ? "Save changes"
              : `Add ${humanize(spec.name)} item`}
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={onCancel}
          class="rounded-md border border-neutral-700 px-3 py-1.5 text-xs text-neutral-300 transition-colors hover:bg-neutral-800 disabled:opacity-40"
        >
          Cancel
        </button>
        {failure && failure.field === null ? (
          <span role="alert" class="text-[11px] text-danger-300">
            {failure.message}
          </span>
        ) : null}
      </div>
    </form>
  );
}

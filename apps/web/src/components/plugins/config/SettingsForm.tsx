import { useEffect, useId, useState } from "preact/hooks";
import {
  PluginConfigError,
  getPluginSettings,
  patchPluginSettings,
} from "@/api/plugins/config/calls";
import type { PluginSchema, RenderedValue } from "@/api/plugins/config/types";
import { SchemaField } from "./SchemaField";
import { bareField } from "./format";

/**
 * The settings of one plugin, painted from its schema.
 *
 * Two rules come straight from the contract:
 *
 * - The write is **partial**: only the keys the user touched are sent, so an
 *   untouched secret is never re-sent (there is no read that returns it).
 * - On failure the form is rolled back to what the server reports and the
 *   server's own `detail` is shown next to the field it names — the form never
 *   keeps a state the server did not confirm.
 */

interface SettingsFormProps {
  plugin: string;
  schema: PluginSchema;
  /** `false` for a token of scope `agent`: a secret cannot be written with it. */
  canWriteSecret: boolean;
  /** Bumped when another client changed this plugin; reloads from the server. */
  reloadKey: number;
}

interface FormFailure {
  message: string;
  field: string | null;
}

function toast(title: string, message: string, severity: "success" | "error" | "info"): void {
  window.dispatchEvent(new CustomEvent("pwnproxy-toast", { detail: { title, message, severity } }));
}

export function SettingsForm({ plugin, schema, canWriteSecret, reloadKey }: SettingsFormProps) {
  const prefix = useId();
  const [values, setValues] = useState<Record<string, RenderedValue> | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<FormFailure | null>(null);
  const [note, setNote] = useState("");

  useEffect(() => {
    let active = true;
    setValues(null);
    setDraft({});
    setFailure(null);
    getPluginSettings(plugin)
      .then((data) => {
        if (!active) return;
        setValues(data.values);
        setLoadError(null);
      })
      .catch((error: unknown) => {
        if (active) setLoadError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      active = false;
    };
  }, [plugin, reloadKey]);

  const dirty = Object.keys(draft).some((key) => draft[key] !== undefined);

  async function save(event: Event): Promise<void> {
    event.preventDefault();
    if (saving) return;
    const payload: Record<string, unknown> = {};
    for (const spec of schema.settings) {
      const value = draft[spec.key];
      if (value === undefined) continue;
      // An untouched secret stays absent: an empty box means "leave it alone".
      if (spec.secret && (typeof value !== "string" || value.length === 0)) continue;
      payload[spec.key] = value;
    }
    if (Object.keys(payload).length === 0) {
      setNote("Nothing to save.");
      return;
    }

    setSaving(true);
    setFailure(null);
    setNote("");
    try {
      const data = await patchPluginSettings(plugin, payload);
      setValues(data.values);
      setDraft({});
      setNote("Saved.");
      toast("Settings saved", `The plugin accepted the change.`, "success");
    } catch (error: unknown) {
      setDraft({});
      const named = error instanceof PluginConfigError ? error.field : null;
      setFailure({
        message: error instanceof Error ? error.message : String(error),
        field: named,
      });
      toast("Could not save the settings", error instanceof Error ? error.message : String(error), "error");
      const target = bareField(named);
      if (target) {
        requestAnimationFrame(() => document.getElementById(`${prefix}-${target}`)?.focus());
      }
    } finally {
      setSaving(false);
    }
  }

  if (loadError !== null) {
    return (
      <p role="alert" class="mt-3 rounded bg-danger-900/30 px-2 py-1 text-[11px] text-danger-300">
        {loadError}
      </p>
    );
  }

  if (values === null) {
    return <p class="mt-3 text-xs text-neutral-500">Loading settings…</p>;
  }

  return (
    <form onSubmit={save} class="mt-3">
      <fieldset class="rounded-md border border-neutral-800 bg-neutral-950 p-3">
        <legend class="px-1 text-xs font-semibold uppercase tracking-wider text-neutral-400">
          Settings
        </legend>
        <div class="grid gap-3 sm:grid-cols-2">
          {schema.settings.map((spec) => (
            <SchemaField
              key={spec.key}
              spec={spec}
              value={values[spec.key]}
              draft={draft[spec.key]}
              idPrefix={prefix}
              disabled={saving || (spec.secret && !canWriteSecret)}
              disabledReason={spec.secret && !canWriteSecret ? "Your token cannot write secrets." : undefined}
              error={failure?.field && bareField(failure.field) === spec.key ? failure.message : null}
              onChange={(value) => {
                setNote("");
                setDraft((previous) => ({ ...previous, [spec.key]: value }));
              }}
            />
          ))}
        </div>
        <div class="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="submit"
            disabled={saving}
            class="rounded-md bg-primary-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
          >
            {saving ? "Saving…" : "Save changes"}
          </button>
          <button
            type="button"
            disabled={saving || !dirty}
            onClick={() => {
              setDraft({});
              setFailure(null);
              setNote("");
            }}
            class="rounded-md border border-neutral-700 px-3 py-1.5 text-xs text-neutral-300 transition-colors hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Discard
          </button>
          <span aria-live="polite" class="text-[11px] text-neutral-500">
            {note}
          </span>
        </div>
        {failure && failure.field === null ? (
          <p role="alert" class="mt-2 rounded bg-danger-900/30 px-2 py-1 text-[11px] text-danger-300">
            {failure.message}
          </p>
        ) : null}
        {!canWriteSecret && schema.settings.some((spec) => spec.secret) ? (
          <p class="mt-2 text-[11px] text-neutral-500">
            Secret fields can only be written from a token of scope “full” (this Web UI, pasted from
            <code class="mx-1 font-mono text-neutral-300">pwnproxy api token</code>).
          </p>
        ) : null}
      </fieldset>
    </form>
  );
}

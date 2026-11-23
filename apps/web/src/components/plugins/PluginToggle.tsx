import { useId, useState } from "preact/hooks";
import type { PluginInfo } from "@/api/plugins/types";
import { pluginOrigin, pluginState, pluginStatus, pluginStatusClass } from "@/utils/plugins";
import { togglePluginWithFeedback } from "./toggleFeedback";

interface PluginToggleProps {
  plugin: PluginInfo;
  /** Called after the server answered, so the caller can reload the catalog. */
  onChanged?: () => void;
}

/**
 * One plugin card: state, origin and reason, plus the activation switch.
 *
 * The switch reflects `plugin.enabled` — the server's effective state — and is
 * never moved on its own: after a toggle the parent reloads the catalog. A
 * broken plugin keeps its switch off and unfocusable-but-readable
 * (`aria-disabled`), because the server answers `409` for it.
 */
export function PluginToggle({ plugin, onChanged }: PluginToggleProps) {
  const [pending, setPending] = useState(false);
  const errorId = useId();
  const state = pluginState(plugin);
  const broken = state === "broken";
  const needsActivation = state === "disabled" && plugin.source === "installed";

  async function handleClick() {
    if (pending || broken) return;
    setPending(true);
    try {
      await togglePluginWithFeedback(plugin.name);
      onChanged?.();
    } finally {
      setPending(false);
    }
  }

  return (
    <div
      class={`rounded-lg border p-3 transition-colors ${
        broken ? "border-danger-800/60 bg-danger-900/10" : "border-neutral-800 bg-neutral-950"
      }`}
    >
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <p
            class={`truncate text-xs font-semibold uppercase tracking-wider ${
              state === "active" ? "text-neutral-200" : "text-neutral-400"
            }`}
            title={plugin.name}
          >
            {plugin.name}
          </p>
          <p class="mt-0.5 text-[11px] text-neutral-500">{pluginOrigin(plugin)}</p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={plugin.enabled}
          aria-label={plugin.name}
          aria-disabled={broken || pending ? "true" : undefined}
          aria-busy={pending ? "true" : undefined}
          aria-describedby={broken ? errorId : undefined}
          onClick={handleClick}
          title={
            broken
              ? "This plugin cannot be turned on while it is broken"
              : plugin.enabled
                ? "Turn off"
                : "Turn on"
          }
          class={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-neutral-950 ${
            plugin.enabled ? "bg-primary-600" : "bg-neutral-700"
          } ${broken ? "cursor-not-allowed opacity-50" : "cursor-pointer"} ${
            pending ? "opacity-60" : ""
          }`}
        >
          <span
            class={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition duration-200 ease-in-out ${
              plugin.enabled ? "translate-x-4" : "translate-x-0.5"
            }`}
          />
        </button>
      </div>

      <p class={`mt-1.5 text-[11px] font-medium ${pluginStatusClass(plugin)}`}>{pluginStatus(plugin)}</p>

      {plugin.description ? (
        <p class="mt-1 line-clamp-2 text-[11px] text-neutral-500" title={plugin.description}>
          {plugin.description}
        </p>
      ) : null}

      {broken ? (
        <p id={errorId} class="mt-1 break-words rounded bg-danger-900/30 px-1.5 py-1 font-mono text-[11px] text-danger-300">
          {plugin.error}
        </p>
      ) : null}

      {needsActivation ? (
        <p class="mt-1 text-[11px] text-neutral-500">
          New packages start disabled so nothing scans without your consent.
        </p>
      ) : null}
    </div>
  );
}

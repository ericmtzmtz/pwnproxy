import { useCallback, useEffect, useState } from "preact/hooks";
import { listPlugins } from "@/api/plugins/calls";
import type { PluginInfo } from "@/api/plugins/types";
import { wsUrl } from "@/api/client";
import { useWebSocket } from "@/hooks/useWebSocket";
import { pluginOrigin, pluginState, pluginStatus, pluginStatusClass } from "@/utils/plugins";
import { togglePluginWithFeedback } from "./toggleFeedback";
import { PluginConfigPanel } from "./config/PluginConfigPanel";

/**
 * The plugins section of Settings: the catalog and, per plugin, its
 * configuration panel.
 *
 * The list comes from `GET /plugins` and the switch calls the toggle — both
 * pre-existing, and the server stays the owner of the state (after a toggle the
 * list is reloaded; nothing is flipped optimistically). The panel is built from
 * the schema (see `./config`), so this file knows no plugin by name.
 *
 * A `plugin.config_changed` event for the plugin whose panel is open (another
 * tab, the CLI or the MCP wrote something) bumps a revision that makes the panel
 * reload from the server. A disabled plugin is still configurable — that is how
 * a plugin is fixed before it can run.
 */

const SWITCH_BASE =
  "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-neutral-950";

function PluginRow({
  plugin,
  open,
  onToggleOpen,
  onToggle,
  pending,
  revision,
}: {
  plugin: PluginInfo;
  open: boolean;
  onToggleOpen: () => void;
  onToggle: () => void;
  pending: boolean;
  revision: number;
}) {
  const state = pluginState(plugin);
  const broken = state === "broken";
  const errorId = `plugin-error-${plugin.name}`;
  const panelId = `plugin-config-${plugin.name}`;

  return (
    <div
      class={`rounded-md border ${broken ? "border-danger-800/60 bg-danger-900/10" : "border-neutral-800 bg-neutral-950"}`}
    >
      <div class="flex items-start justify-between gap-3 px-3 py-2.5">
        <div class="min-w-0">
          <p class={`text-sm font-medium ${plugin.enabled ? "text-neutral-200" : "text-neutral-400"}`}>
            {plugin.name}
          </p>
          <p class="text-[11px] text-neutral-500">{pluginOrigin(plugin)}</p>
          <p class={`mt-0.5 text-[11px] font-medium ${pluginStatusClass(plugin)}`}>{pluginStatus(plugin)}</p>
          {plugin.description ? (
            <p class="mt-1 text-[11px] text-neutral-500">{plugin.description}</p>
          ) : null}
          {broken && plugin.error ? (
            <p
              id={errorId}
              class="mt-1 break-words rounded bg-danger-900/30 px-1.5 py-1 font-mono text-[11px] text-danger-300"
            >
              {plugin.error}
            </p>
          ) : null}
        </div>

        <div class="flex shrink-0 items-center gap-2">
          <button
            type="button"
            role="switch"
            aria-checked={plugin.enabled}
            aria-label={`${plugin.name} activation`}
            aria-disabled={broken || pending ? "true" : undefined}
            aria-busy={pending ? "true" : undefined}
            aria-describedby={broken ? errorId : undefined}
            onClick={onToggle}
            title={
              broken
                ? "This plugin cannot be turned on while it is broken"
                : plugin.enabled
                  ? "Turn off"
                  : "Turn on"
            }
            class={`${SWITCH_BASE} ${plugin.enabled ? "bg-primary-600" : "bg-neutral-700"} ${
              broken ? "cursor-not-allowed opacity-50" : "cursor-pointer"
            } ${pending ? "opacity-60" : ""}`}
          >
            <span
              class={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform duration-200 ${
                plugin.enabled ? "translate-x-6" : "translate-x-1"
              }`}
            />
          </button>

          <button
            type="button"
            aria-expanded={open}
            aria-controls={panelId}
            onClick={onToggleOpen}
            class="rounded-md border border-neutral-700 px-2.5 py-1 text-[11px] text-neutral-300 transition-colors hover:bg-neutral-800 hover:text-neutral-100"
          >
            {open ? "Hide settings" : "Configure"}
          </button>
        </div>
      </div>

      <div id={panelId} class="px-3 pb-3">
        {open ? <PluginConfigPanel plugin={plugin} reloadKey={revision} /> : null}
      </div>
    </div>
  );
}

export function PluginsSection() {
  const [plugins, setPlugins] = useState<PluginInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);

  const load = useCallback(async () => {
    try {
      const data = await listPlugins();
      setPlugins(data.plugins);
      setError(data.error);
    } catch (err: unknown) {
      setPlugins([]);
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useWebSocket({
    url: wsUrl("/ws/events"),
    onMessage(msg) {
      if (msg.type !== "plugin.config_changed") return;
      // Only the open panel reloads; every write names its plugin.
      if (typeof msg.plugin === "string" && msg.plugin === selected) {
        setRevision((current) => current + 1);
      }
    },
  });

  async function toggle(plugin: PluginInfo) {
    if (pending !== null) return;
    setPending(plugin.name);
    try {
      await togglePluginWithFeedback(plugin.name);
      await load();
    } finally {
      setPending(null);
    }
  }

  const active = plugins.filter((plugin) => plugin.enabled).length;

  return (
    <div>
      <div class="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <p class="max-w-prose text-xs text-neutral-500">
          Scanner plugins found on this machine, built-in and installed. Activation is machine-wide
          and survives sessions; each plugin publishes the settings, lists and actions it accepts.
        </p>
        <span class="text-[11px] font-medium text-neutral-400">
          {plugins.length > 0 ? `${active} of ${plugins.length} active` : ""}
        </span>
      </div>

      <div class="space-y-2" aria-busy={loaded ? undefined : "true"}>
        {error !== null ? (
          <div role="alert" class="rounded-md border border-danger-800 bg-danger-900/20 px-3 py-2">
            <p class="text-xs font-medium text-danger-400">Plugin catalog unavailable</p>
            <p class="mt-0.5 break-words text-[11px] text-neutral-400">{error}</p>
          </div>
        ) : plugins.length === 0 ? (
          <p class="py-8 text-center text-sm text-neutral-600">
            {loaded ? "No plugins discovered" : "Loading plugins…"}
          </p>
        ) : (
          plugins.map((plugin) => (
            <PluginRow
              key={plugin.name}
              plugin={plugin}
              open={selected === plugin.name}
              onToggleOpen={() => setSelected((current) => (current === plugin.name ? null : plugin.name))}
              onToggle={() => void toggle(plugin)}
              pending={pending === plugin.name}
              revision={revision}
            />
          ))
        )}
      </div>
    </div>
  );
}

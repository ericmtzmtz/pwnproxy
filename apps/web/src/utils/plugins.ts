import type { PluginInfo } from "@/api/plugins/types";

/**
 * How a plugin is rendered in the UI.
 *
 * `broken` wins over everything else: a plugin whose discovery or `on_load`
 * failed is reported with `error` and an *effective* `enabled: false`, and the
 * toggle answers `409`, so the control must stay off and explain the reason.
 */
export type PluginState = "active" | "disabled" | "broken";

export function pluginState(plugin: PluginInfo): PluginState {
  if (plugin.error !== null && plugin.error.length > 0) return "broken";
  return plugin.enabled ? "active" : "disabled";
}

/** Where the plugin comes from, in words (never the raw `builtin`/`installed` id). */
export function pluginOrigin(plugin: PluginInfo): string {
  if (plugin.source === "installed") {
    const pkg = plugin.package ?? "unknown package";
    return plugin.version ? `Installed · ${pkg} ${plugin.version}` : `Installed · ${pkg}`;
  }
  return "Built-in";
}

/** One-line state for the plugin card. Broken plugins get their reason separately. */
export function pluginStatus(plugin: PluginInfo): string {
  const state = pluginState(plugin);
  if (state === "broken") return "Broken — cannot be turned on";
  if (state === "active") return "Active";
  // An installed plugin starts off on purpose: say so instead of a bare "Disabled".
  if (plugin.source === "installed") return "Installed but not activated — turn it on to scan";
  return "Disabled";
}

/** Tailwind tone for the state line. */
export function pluginStatusClass(plugin: PluginInfo): string {
  const state = pluginState(plugin);
  if (state === "broken") return "text-danger-400";
  if (state === "active") return "text-success-500";
  return plugin.source === "installed" ? "text-primary-300" : "text-neutral-500";
}

/**
 * Types for `GET /api/v1/plugins` (see `pwnproxy/transport/rest/plugins.py`).
 *
 * The server decides the state: `enabled` is the *effective* one (an installed
 * package starts off and a broken plugin reports `false`) and the order is
 * already resolved (built-ins first, then `name` ascending). The client only
 * renders this — it never recomputes `enabled` or sorts.
 */
export type PluginSource = "builtin" | "installed";

/** Obligatory fields, always present for every plugin in the catalog. */
export interface PluginInfo {
  name: string;
  source: PluginSource;
  package: string | null;
  version: string | null;
  enabled: boolean;
  error: string | null;
  /** Optional metadata captured at discovery time. */
  category?: string;
  description?: string;
  author?: string;
  consumes?: string[];
  produces?: string[];
  /** Whether this process has the plugin loaded right now. */
  loaded?: boolean;
}

export interface PluginListResponse {
  plugins: PluginInfo[];
  /** Non-null when the catalog could not be built (e.g. no plugin loader). */
  error: string | null;
}

export interface ToggleResponse {
  status: "enabled" | "disabled";
  name: string;
}

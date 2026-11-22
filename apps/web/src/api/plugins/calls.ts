import { API_BASE } from "@/core";
import type { PluginListResponse, ToggleResponse } from "./types";

/**
 * Failure of `POST /plugins/{name}/toggle`, carrying the HTTP status so the UI
 * can explain *why* without guessing: `404` the name is not in the catalog,
 * `409` the plugin exists but cannot run, `500` the config could not be saved.
 */
export class PluginToggleError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "PluginToggleError";
    this.status = status;
  }
}

function serverDetail(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const detail = (body as Record<string, unknown>)["detail"];
  return typeof detail === "string" && detail.length > 0 ? detail : null;
}

/** Every plugin in the catalog, disabled and broken ones included. Never 4xx/5xx. */
export async function listPlugins(): Promise<PluginListResponse> {
  const res = await fetch(`${API_BASE}/plugins`);
  if (!res.ok) {
    throw new Error(`Failed to list plugins: ${res.statusText}`);
  }
  return res.json();
}

/** Flip a plugin's activation. Machine-wide; the server decides the new state. */
export async function togglePlugin(name: string): Promise<ToggleResponse> {
  const res = await fetch(`${API_BASE}/plugins/${encodeURIComponent(name)}/toggle`, {
    method: "POST",
  });
  if (!res.ok) {
    const body: unknown = await res.json().catch(() => null);
    const fallback = res.statusText.length > 0 ? res.statusText : `HTTP ${res.status}`;
    throw new PluginToggleError(res.status, serverDetail(body) ?? fallback);
  }
  return res.json();
}

import { API_BASE } from "@/core";
import type { PluginListResponse, ToggleResponse } from "./types";

export async function listPlugins(): Promise<PluginListResponse> {
  const res = await fetch(`${API_BASE}/plugins`);
  if (!res.ok) {
    throw new Error(`Failed to list plugins: ${res.statusText}`);
  }
  return res.json();
}

export async function togglePlugin(name: string): Promise<ToggleResponse> {
  const res = await fetch(`${API_BASE}/plugins/${name}/toggle`, {
    method: "POST",
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to toggle plugin");
  }
  return res.json();
}

import { API_BASE } from "@/core";

export interface ScopeConfig {
  in_scope: string[];
  out_of_scope: string[];
  enabled: boolean;
}

export async function getScope(): Promise<ScopeConfig> {
  const res = await fetch(`${API_BASE}/sessions/scope`);
  if (!res.ok) throw new Error(`Failed to get scope: ${res.statusText}`);
  return res.json();
}

export async function updateScope(scope: ScopeConfig): Promise<void> {
  const res = await fetch(`${API_BASE}/sessions/scope`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(scope),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to update scope");
  }
}

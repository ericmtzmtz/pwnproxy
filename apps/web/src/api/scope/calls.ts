import { API_BASE } from "@/core";
import { apiFetch } from "@/api/client";

export interface ScopeConfig {
  in_scope: string[];
  out_of_scope: string[];
  enabled: boolean;
  /**
   * Server verdict: may automatically captured traffic reach the active
   * scanners? Computed by the backend (`ScopeConfig.active_scan_allowed`);
   * the UI never recomputes it — it renders the verdict and the reason below.
   */
  active_scan_allowed: boolean;
  /** Why active scanning is paused, in words; `null` when it is allowed. */
  active_scan_blocked_reason: string | null;
}

export async function getScope(): Promise<ScopeConfig> {
  const res = await apiFetch(`${API_BASE}/sessions/scope`);
  if (!res.ok) throw new Error(`Failed to get scope: ${res.statusText}`);
  return res.json();
}

export async function updateScope(scope: ScopeConfig): Promise<void> {
  const res = await apiFetch(`${API_BASE}/sessions/scope`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      in_scope: scope.in_scope,
      out_of_scope: scope.out_of_scope,
      enabled: scope.enabled,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to update scope");
  }
}

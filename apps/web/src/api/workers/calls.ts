import { API_BASE } from "@/core";
import { apiFetch } from "@/api/client";

export interface WorkersResponse {
  tasks: {
    id: string;
    type: string;
    status: string;
    progress: number;
    total: number;
    created_at: string | null;
  }[];
  crawler_jobs: { id: unknown; type: string; status: string; created_at: string | null }[];
  autoscan: {
    running: boolean;
    active: { batch_id: string | null; flows: number; findings: number; duration_ms: number } | null;
    last: { batch_id: string | null; flows: number; findings: number; duration_ms: number } | null;
  };
  proxy: { running: boolean; port: number | null; capture_enabled: boolean };
  /**
   * Same verdict as `GET /sessions/scope`: `false` means the auto-scan is
   * paused (scope off or no include rules) and `active_scan_blocked_reason`
   * carries the sentence to show. Server-owned; never derived here.
   */
  active_scan_allowed: boolean;
  active_scan_blocked_reason: string | null;
}

export async function getWorkers(): Promise<WorkersResponse> {
  const res = await apiFetch(`${API_BASE}/workers`);
  if (!res.ok) throw new Error(`Failed to get workers status: ${res.statusText}`);
  return res.json();
}

import { API_BASE } from "@/core";

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
}

export async function getWorkers(): Promise<WorkersResponse> {
  const res = await fetch(`${API_BASE}/workers`);
  if (!res.ok) throw new Error(`Failed to get workers status: ${res.statusText}`);
  return res.json();
}

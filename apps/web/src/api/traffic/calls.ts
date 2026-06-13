import { API_BASE } from "@/core";
import type { FlowRecord } from "./types";

export async function listFlows(limit = 50, offset = 0): Promise<FlowRecord[]> {
  const res = await fetch(`${API_BASE}/flows?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error(`Failed to list flows: ${res.statusText}`);
  return res.json();
}

export async function listFlowsSince(sinceId: number): Promise<FlowRecord[]> {
  const res = await fetch(`${API_BASE}/flows?since_id=${sinceId}`);
  if (!res.ok) throw new Error(`Failed to list flows: ${res.statusText}`);
  return res.json();
}

export async function getFlow(id: number): Promise<FlowRecord> {
  const res = await fetch(`${API_BASE}/flows/${id}`);
  if (!res.ok) throw new Error(`Flow ${id} not found`);
  return res.json();
}

export async function deleteFlow(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/flows/${id}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`Failed to delete flow ${id}`);
}

export async function clearFlows(): Promise<void> {
  const res = await fetch(`${API_BASE}/flows`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error("Failed to clear flows");
}

export async function outscopeFlow(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/flows/${id}/outscope`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  if (!res.ok) throw new Error(`Failed to outscope flow ${id}`);
}

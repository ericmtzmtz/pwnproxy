import { API_BASE } from "@/core";
import type { TriggerRequest, TriggerResponse, FlowTriggerRequest, FlowTriggerResponse } from "./types";

export async function triggerScanner(body: TriggerRequest): Promise<TriggerResponse> {
  const res = await fetch(`${API_BASE}/scanners/trigger`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to trigger scanner");
  }
  return res.json();
}

export async function triggerFlowScan(body: FlowTriggerRequest): Promise<FlowTriggerResponse> {
  const res = await fetch(`${API_BASE}/scanners/trigger-flow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to trigger flow scan");
  }
  return res.json();
}

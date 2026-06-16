import type { InterceptStatus, PendingFlow } from "./types";
import { API_BASE } from "@/core";

export async function getStatus(): Promise<InterceptStatus> {
  const res = await fetch(`${API_BASE}/interceptor/status`);
  if (!res.ok) throw new Error("Failed to get interceptor status");
  return res.json();
}

export async function toggleIntercept(): Promise<InterceptStatus> {
  const res = await fetch(`${API_BASE}/interceptor/toggle`, { method: "PUT" });
  if (!res.ok) throw new Error("Failed to toggle interceptor");
  return res.json();
}

export async function getPending(): Promise<PendingFlow[]> {
  const res = await fetch(`${API_BASE}/interceptor/pending`);
  if (!res.ok) throw new Error("Failed to get pending flows");
  return res.json();
}

export async function forwardFlow(flowId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/interceptor/forward/${flowId}`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to forward flow");
}

export async function dropFlow(flowId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/interceptor/drop/${flowId}`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to drop flow");
}

export async function forwardAll(): Promise<{ count: number }> {
  const res = await fetch(`${API_BASE}/interceptor/forward-all`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to forward all");
  return res.json();
}

export async function dropAll(): Promise<{ count: number }> {
  const res = await fetch(`${API_BASE}/interceptor/drop-all`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to drop all");
  return res.json();
}

import { API_BASE } from "@/core";
import { apiFetch } from "@/api/client";
import type { ProxyStatus } from "./types";

export async function getProxyStatus(): Promise<ProxyStatus> {
  const res = await apiFetch(`${API_BASE}/proxy/status`);
  if (!res.ok) throw new Error("Failed to get proxy status");
  return res.json();
}

export async function startProxy(): Promise<ProxyStatus> {
  const res = await apiFetch(`${API_BASE}/proxy/start`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to start proxy");
  return res.json();
}

export async function stopProxy(): Promise<void> {
  const res = await apiFetch(`${API_BASE}/proxy/stop`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to stop proxy");
}

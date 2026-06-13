import { API_BASE } from "@/core";
import type { ProxyStatus } from "./types";

export async function getProxyStatus(): Promise<ProxyStatus> {
  const res = await fetch(`${API_BASE}/proxy/status`);
  if (!res.ok) throw new Error("Failed to get proxy status");
  return res.json();
}

export async function startProxy(): Promise<ProxyStatus> {
  const res = await fetch(`${API_BASE}/proxy/start`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to start proxy");
  return res.json();
}

export async function stopProxy(): Promise<void> {
  const res = await fetch(`${API_BASE}/proxy/stop`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to stop proxy");
}

export async function toggleProxy(): Promise<ProxyStatus> {
  const res = await fetch(`${API_BASE}/proxy/toggle`, { method: "PUT" });
  if (!res.ok) throw new Error("Failed to toggle proxy");
  return res.json();
}

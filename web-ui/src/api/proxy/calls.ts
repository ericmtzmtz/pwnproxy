import { API_BASE } from "@/core";
import type { ProxyStatus } from "./types";

export async function getProxyStatus(): Promise<ProxyStatus> {
  const res = await fetch(`${API_BASE}/proxy/status`);
  if (!res.ok) throw new Error("Failed to get proxy status");
  return res.json();
}

export async function toggleProxy(): Promise<ProxyStatus> {
  const res = await fetch(`${API_BASE}/proxy/toggle`, { method: "PUT" });
  if (!res.ok) throw new Error("Failed to toggle proxy");
  return res.json();
}

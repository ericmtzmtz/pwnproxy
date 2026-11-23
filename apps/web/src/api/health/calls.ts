import { API_BASE } from "@/core";
import { apiFetch } from "@/api/client";
import type { HealthResponse } from "./types";

export async function getHealth(): Promise<HealthResponse> {
  const res = await apiFetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error("Failed to get health");
  return res.json();
}

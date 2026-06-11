import { API_BASE } from "@/core";
import type { PaginatedFindings } from "./types";

export async function listFindings(
  page = 1,
  perPage = 20,
  severity?: string,
): Promise<PaginatedFindings> {
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage) });
  if (severity) params.set("severity", severity);
  const res = await fetch(`${API_BASE}/findings?${params}`);
  if (!res.ok) throw new Error(`Failed to list findings: ${res.statusText}`);
  return res.json();
}

export async function listFindingsSince(sinceId: number): Promise<PaginatedFindings> {
  const res = await fetch(`${API_BASE}/findings?page=1&per_page=100&since_id=${sinceId}`);
  if (!res.ok) throw new Error(`Failed to list findings: ${res.statusText}`);
  return res.json();
}

export async function deleteFinding(scanner: string, id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/findings/${scanner}/${id}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`Failed to delete finding`);
}

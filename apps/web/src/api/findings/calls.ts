import { API_BASE } from "@/core";
import type { PaginatedFindings, TriageVerdict } from "./types";

export async function listFindings(
  page = 1,
  perPage = 20,
  severity?: string,
  verdict?: string,
): Promise<PaginatedFindings> {
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage) });
  if (severity) params.set("severity", severity);
  if (verdict) params.set("verdict", verdict);
  const res = await fetch(`${API_BASE}/findings?${params}`);
  if (!res.ok) throw new Error(`Failed to list findings: ${res.statusText}`);
  return res.json();
}

export async function triageFeedback(
  id: number,
  verdict: Extract<TriageVerdict, "true_positive" | "false_positive">,
  reason?: string,
): Promise<void> {
  const res = await fetch(`${API_BASE}/findings/${id}/feedback`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ verdict, reason }),
  });
  if (!res.ok) throw new Error(`Failed to submit feedback: ${res.statusText}`);
}

export async function listFindingsSince(sinceId: number): Promise<PaginatedFindings> {
  const res = await fetch(`${API_BASE}/findings?page=1&per_page=100&since_id=${sinceId}`);
  if (!res.ok) throw new Error(`Failed to list findings: ${res.statusText}`);
  return res.json();
}

export async function deleteFinding(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/findings/${id}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`Failed to delete finding`);
}

export async function deleteFindings(ids: number[]): Promise<void> {
  if (ids.length === 0) return;
  const res = await fetch(`${API_BASE}/findings?ids=${ids.join(",")}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`Failed to delete findings`);
}

export async function deleteAllFindings(): Promise<void> {
  const res = await fetch(`${API_BASE}/findings`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`Failed to delete findings`);
}

import { API_BASE } from "@/core";
import type { FindingRow, ReportGenerateRequest, ReportGenerateResponse } from "./types";

export async function listAllFindings(limit = 100): Promise<FindingRow[]> {
  const res = await fetch(`${API_BASE}/findings?limit=${limit}`);
  if (!res.ok) throw new Error("Failed to fetch findings");
  return res.json();
}

export async function listScannerFindings(scanner: string, limit = 100, offset = 0): Promise<FindingRow[]> {
  const res = await fetch(`${API_BASE}/findings/${scanner}?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error(`Failed to fetch ${scanner} findings`);
  return res.json();
}

export async function generateReport(body: ReportGenerateRequest): Promise<ReportGenerateResponse> {
  const res = await fetch(`${API_BASE}/reports/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => null);
    throw new Error(detail?.detail ?? "Failed to start report generation");
  }
  return res.json();
}

export function reportDownloadUrl(taskId: string, format: string): string {
  return `${API_BASE}/reports/${taskId}/download?format=${format}`;
}

import { API_BASE } from "@/core";
import type { FindingRow } from "./types";

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

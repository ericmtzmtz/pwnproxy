import { API_BASE } from "@/core";
import type { BruteforceStartRequest, CrawlStatus, WordlistInfo } from "./types";

export async function startBruteforce(req: BruteforceStartRequest): Promise<{ job_id: number; status: string; total_estimated: number }> {
  const res = await fetch(`${API_BASE}/bruteforce/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to start bruteforce");
  }
  return res.json();
}

export async function stopBruteforce(): Promise<{ stopped: boolean; job_id?: number }> {
  const res = await fetch(`${API_BASE}/bruteforce/stop`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to stop bruteforce");
  return res.json();
}

export async function getBruteforceStatus(): Promise<CrawlStatus> {
  const res = await fetch(`${API_BASE}/crawler/status`);
  if (!res.ok) throw new Error("Failed to get status");
  return res.json();
}

export async function listWordlists(): Promise<{ wordlists: WordlistInfo[] }> {
  const res = await fetch(`${API_BASE}/bruteforce/wordlists`);
  if (!res.ok) throw new Error("Failed to list wordlists");
  return res.json();
}

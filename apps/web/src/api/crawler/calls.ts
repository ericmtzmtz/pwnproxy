import { API_BASE } from "@/core";
import type { PaginatedDiscoveredUrls, CrawlStartRequest, CrawlStatus } from "./types";

export async function listDiscoveredUrls(
  page = 1,
  perPage = 50,
  source?: string,
): Promise<PaginatedDiscoveredUrls> {
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage) });
  if (source) params.set("source", source);
  const res = await fetch(`${API_BASE}/crawler/urls?${params}`);
  if (!res.ok) throw new Error(`Failed to list crawler URLs: ${res.statusText}`);
  return res.json();
}

export async function startCrawl(req: CrawlStartRequest): Promise<{ job_id: number; status: string }> {
  const res = await fetch(`${API_BASE}/crawler/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to start crawl");
  }
  return res.json();
}

export async function stopCrawl(): Promise<{ stopped: boolean; job_id?: number }> {
  const res = await fetch(`${API_BASE}/crawler/stop`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to stop crawl");
  return res.json();
}

export async function getCrawlStatus(): Promise<CrawlStatus> {
  const res = await fetch(`${API_BASE}/crawler/status`);
  if (!res.ok) throw new Error("Failed to get crawl status");
  return res.json();
}

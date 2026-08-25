import { API_BASE } from "@/core";
import type { PaginatedDiscoveredUrls } from "./types";

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

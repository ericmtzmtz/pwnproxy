import { API_BASE } from "@/core";
import type { LaunchResponse, ScanTask, BurpImportResponse, ScanLaunchOptions } from "./types";

export async function launchScan(url: string, scanners = "", opts?: ScanLaunchOptions): Promise<LaunchResponse> {
  const params = new URLSearchParams({ url });
  if (scanners) params.set("scanners", scanners);
  if (opts?.method) params.set("method", opts.method);
  if (opts?.body) params.set("body", opts.body);
  if (opts?.content_type) params.set("content_type", opts.content_type);
  if (opts?.cookies) params.set("cookies", opts.cookies);
  const res = await fetch(`${API_BASE}/scan?${params}`, { method: "POST" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to launch scan");
  }
  return res.json();
}

export async function pollScan(scanId: string): Promise<ScanTask> {
  const res = await fetch(`${API_BASE}/scan/${scanId}`);
  if (!res.ok) {
    throw new Error(`Scan ${scanId} not found`);
  }
  return res.json();
}

export async function importBurpConfig(configJson: string): Promise<BurpImportResponse> {
  const res = await fetch(`${API_BASE}/import/burp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ config: configJson }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to import Burp config");
  }
  return res.json();
}

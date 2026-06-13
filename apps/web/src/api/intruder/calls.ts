import { API_BASE } from "@/core";
import type { IntruderRunRequest, IntruderRunResponse, WordlistEntry } from "./types";

export async function runIntruder(body: IntruderRunRequest): Promise<IntruderRunResponse> {
  const res = await fetch(`${API_BASE}/intruder/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to run intruder");
  }
  return res.json();
}

export async function listWordlists(dir = ""): Promise<WordlistEntry[]> {
  const params = dir ? `?dir=${encodeURIComponent(dir)}` : "";
  const res = await fetch(`${API_BASE}/intruder/wordlists${params}`);
  if (!res.ok) throw new Error("Failed to list wordlists");
  return res.json();
}

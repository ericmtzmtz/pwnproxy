import { API_BASE } from "@/core";
import type { RepeaterRequest, RepeaterResponse } from "./types";

export async function sendRequest(body: RepeaterRequest): Promise<RepeaterResponse> {
  const res = await fetch(`${API_BASE}/repeater/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to send request");
  }
  return res.json();
}

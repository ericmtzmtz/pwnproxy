import { API_BASE } from "@/core";
import type { RepeaterRequest, RepeaterResponse, RepeaterTab, CreateRepeaterTab, UpdateRepeaterTab } from "./types";

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

export async function listTabs(): Promise<RepeaterTab[]> {
  const res = await fetch(`${API_BASE}/repeater/tabs`);
  if (!res.ok) throw new Error("Failed to list tabs");
  return res.json();
}

export async function createTab(body: CreateRepeaterTab): Promise<RepeaterTab> {
  const res = await fetch(`${API_BASE}/repeater/tabs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "Failed to create tab");
  }
  return res.json();
}

export async function updateTab(id: number, body: UpdateRepeaterTab): Promise<RepeaterTab> {
  const res = await fetch(`${API_BASE}/repeater/tabs/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `Failed to update tab ${id}`);
  }
  return res.json();
}

export async function deleteTab(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/repeater/tabs/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Failed to delete tab ${id}`);
}

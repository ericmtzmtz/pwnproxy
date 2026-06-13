import { API_BASE } from "@/core";
import type { TaskListResponse, TaskStatus } from "./types";

export async function pollTask(taskId: string): Promise<TaskStatus> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}`);
  if (!res.ok) throw new Error(`Task ${taskId} not found`);
  return res.json();
}

export async function listTasks(type?: string, limit = 50): Promise<TaskListResponse> {
  const params = new URLSearchParams();
  if (type) params.set("type", type);
  params.set("limit", String(limit));
  const res = await fetch(`${API_BASE}/tasks?${params}`);
  if (!res.ok) throw new Error("Failed to list tasks");
  return res.json();
}

export async function cancelTask(taskId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}/cancel`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to cancel task ${taskId}`);
}

export async function deleteTask(taskId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}`, { method: "DELETE" });
  if (!res.ok && res.status !== 204) throw new Error(`Failed to delete task ${taskId}`);
}

import { API_BASE } from "@/core";
import type { TaskListDetailResponse, TaskListResponse, TaskStatus } from "./types";

export async function pollTask(taskId: string): Promise<TaskStatus> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}`);
  if (!res.ok) throw new Error(`Task ${taskId} not found`);
  return res.json();
}

export interface ListTasksOptions {
  type?: string;
  limit?: number;
  /** Inline each task's `config`/`result` (one request for the whole list). */
  detail?: boolean;
}

/** One request for the whole list, each item carrying its config and result. */
export function listTasks(options: { type?: string; limit?: number; detail: true }): Promise<TaskListDetailResponse>;
export function listTasks(options?: { type?: string; limit?: number; detail?: false }): Promise<TaskListResponse>;
export function listTasks(type?: string, limit?: number): Promise<TaskListResponse>;
export async function listTasks(
  typeOrOptions?: string | ListTasksOptions,
  limit = 50,
): Promise<TaskListResponse | TaskListDetailResponse> {
  const opts: ListTasksOptions =
    typeof typeOrOptions === "string" || typeOrOptions === undefined
      ? { type: typeOrOptions, limit }
      : typeOrOptions;
  const params = new URLSearchParams();
  if (opts.type) params.set("type", opts.type);
  params.set("limit", String(opts.limit ?? 50));
  if (opts.detail) params.set("detail", "true");
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

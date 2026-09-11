import { API_BASE } from "@/core";
import type { Comment, CommentCreatePayload, CommentUpdatePayload } from "./types";

export async function listComments(flowId: number): Promise<Comment[]> {
  const res = await fetch(`${API_BASE}/flows/${flowId}/comments`);
  if (!res.ok) throw new Error(`Failed to list comments for flow ${flowId}: ${res.statusText}`);
  return res.json();
}

export async function createComment(flowId: number, payload: CommentCreatePayload): Promise<Comment> {
  const res = await fetch(`${API_BASE}/flows/${flowId}/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Failed to create comment: ${res.statusText}`);
  return res.json();
}

export async function updateComment(
  flowId: number,
  commentId: number,
  payload: CommentUpdatePayload,
): Promise<Comment> {
  const res = await fetch(`${API_BASE}/flows/${flowId}/comments/${commentId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Failed to update comment ${commentId}: ${res.statusText}`);
  return res.json();
}

export async function deleteComment(flowId: number, commentId: number): Promise<void> {
  const res = await fetch(`${API_BASE}/flows/${flowId}/comments/${commentId}`, {
    method: "DELETE",
  });
  if (!res.ok && res.status !== 204) throw new Error(`Failed to delete comment ${commentId}: ${res.statusText}`);
}

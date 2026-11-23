import { API_BASE } from "@/core";
import { apiFetch } from "@/api/client";

/** Answer of `GET /api/v1/auth/whoami` — the token's scope, nothing else. */
export interface WhoAmI {
  scope: "full" | "agent";
}

/** The server's fixed `detail` string, when the body carries one. */
function serverDetail(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const detail = (body as Record<string, unknown>)["detail"];
  return typeof detail === "string" && detail.length > 0 ? detail : null;
}

/**
 * Prove the stored token is accepted before letting the UI load.
 *
 * `401` means the pasted token is wrong or was rotated; any other non-2xx is an
 * API problem (for instance the server's `503` "no token configured") and its
 * own message is the most useful thing to show.
 */
export async function whoAmI(): Promise<WhoAmI> {
  const res = await apiFetch(`${API_BASE}/auth/whoami`);
  if (res.status === 401) throw new Error("The token was rejected by the API.");
  if (!res.ok) {
    const body: unknown = await res.json().catch(() => null);
    throw new Error(serverDetail(body) ?? `The API answered with status ${res.status}.`);
  }
  return res.json();
}

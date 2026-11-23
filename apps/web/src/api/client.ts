/**
 * The only place in the Web UI that talks to the network.
 *
 * Every HTTP request goes through {@link apiFetch} and every WebSocket through
 * {@link wsProtocols}, so the API token is attached in exactly one place:
 *
 * - HTTP: `Authorization: Bearer <token>` on every `/api/v1/*` request.
 * - WebSocket: the token travels in the `Sec-WebSocket-Protocol` header (the
 *   browser cannot set headers on a socket, and a token in the query string
 *   ends up in access logs, `Referer` and history — the server never reads it).
 * - No token, a `401` answer or a `4401` socket close all land on the same
 *   screen ("Paste the token"), which re-asks for the token and reloads.
 *
 * `tests/architecture/test_web_api_client.py` fails if the raw `fetch` call or
 * the `WebSocket` constructor shows up anywhere else under `apps/web/src`.
 *
 * The token is **never** baked into the bundle: it is read from `localStorage`
 * at runtime (key {@link TOKEN_STORAGE_KEY}), where it arrived from the
 * `#token=…` fragment. `localStorage` and not `sessionStorage` is a decided
 * trade-off: a XSS in this origin can read either one, and `sessionStorage`
 * would force pasting the token in every tab.
 */

import { API_BASE } from "@/core";

/**
 * `localStorage` key that holds the API token.
 *
 * Must stay equal to `TOKEN_STORAGE_KEY` in `pwnproxy/transport/rest/docs.py`
 * so the `/docs` page and this UI share one pasted token.
 */
export const TOKEN_STORAGE_KEY = "pwnproxy.api.token";

/** Fired on `window` when the API rejected the stored token; the gate listens. */
export const UNAUTHORIZED_EVENT = "pwnproxy:unauthorized";

/** Fired on `window` once a token is stored, so idle sockets can connect. */
export const TOKEN_CHANGED_EVENT = "pwnproxy:token";

/** Subprotocol the server always answers on a successful handshake. */
const WS_SUBPROTOCOL = "pwnproxy";

/** Prefix of the subprotocol that carries the token (mirrors the server). */
const WS_TOKEN_PREFIX = "pwnproxy-token.";

/**
 * Body the wrapper answers with when there is no token at all.
 *
 * Byte-for-byte the server's fixed `401` body, so callers cannot tell the
 * difference between "the wrapper refused to send" and "the API said no".
 */
const MISSING_TOKEN_BODY = JSON.stringify({ detail: "Missing or invalid API token" });

function storage(): Storage | null {
  // `typeof window` first: Node exposes a `localStorage` global that warns when
  // touched during Astro's server render, so it is never read there.
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    // Storage access throws when cookies/site data are blocked.
    return null;
  }
}

/** The stored token, or `null` when there is none (or storage is blocked). */
export function getToken(): string | null {
  const store = storage();
  if (!store) return null;
  try {
    const token = store.getItem(TOKEN_STORAGE_KEY)?.trim() ?? "";
    return token.length > 0 ? token : null;
  } catch {
    return null;
  }
}

/** Store a token (trimmed) and announce it so sockets reconnect. */
export function setToken(token: string): void {
  const clean = token.trim();
  if (clean.length === 0) {
    clearToken();
    return;
  }
  const store = storage();
  if (!store) return;
  try {
    store.setItem(TOKEN_STORAGE_KEY, clean);
  } catch {
    // Quota or blocked storage: the gate will ask again on the next request.
    return;
  }
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(TOKEN_CHANGED_EVENT));
  }
}

/** Forget the stored token. Safe to call when there is none. */
export function clearToken(): void {
  const store = storage();
  if (!store) return;
  try {
    store.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Nothing else to do: the next request still fails with 401.
  }
}

/**
 * Drop the token and tell the UI to ask for a new one.
 *
 * Called on a `401` HTTP answer and on a `4401` socket close; the gate listens
 * for {@link UNAUTHORIZED_EVENT} and takes over the screen.
 */
export function reportUnauthorized(): void {
  clearToken();
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
  }
}

/**
 * `fetch` with the API token attached.
 *
 * Without a token it sends **nothing** (a token-less request would only feed
 * the server's `401` path) and answers the same fixed `401` body the API uses,
 * so every caller keeps its existing `res.ok` handling. On a real `401` the
 * token is forgotten and the gate takes over the screen; otherwise the response
 * is returned untouched.
 */
export async function apiFetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
  const token = getToken();
  if (!token) {
    return new Response(MISSING_TOKEN_BODY, {
      status: 401,
      statusText: "Unauthorized",
      headers: { "Content-Type": "application/json" },
    });
  }

  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);

  const response = await fetch(input, { ...init, headers });
  if (response.status === 401) reportUnauthorized();
  return response;
}

/**
 * Subprotocols to offer on a WebSocket handshake.
 *
 * The server answers `pwnproxy` and never echoes the token; without the second
 * entry it accepts and closes with `4401`.
 */
export function wsProtocols(): string[] {
  const token = getToken();
  return token ? [WS_SUBPROTOCOL, `${WS_TOKEN_PREFIX}${token}`] : [WS_SUBPROTOCOL];
}

/**
 * Absolute `ws://`/`wss://` URL for an API path (`/ws/events`).
 *
 * Derived from {@link API_BASE} so the socket always follows the same origin as
 * the HTTP calls, including a relative `PUBLIC_API_BASE` behind nginx.
 */
export function wsUrl(path: string): string {
  const fallback = "http://127.0.0.1";
  const base = new URL(
    API_BASE,
    typeof window === "undefined" ? fallback : window.location.href,
  );
  const scheme = base.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${base.host}${path}`;
}

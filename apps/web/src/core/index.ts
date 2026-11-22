/**
 * Single source of truth for the API location in the Web UI.
 *
 * `PUBLIC_API_BASE` (build-time / `npm run dev -- --backend`) always wins; the
 * fallback lives here only, so components never repeat a port literal.
 * Keep the port in sync with `DEFAULT_API_PORT` in `pwnproxy/shared/ports.py`;
 * `tests/architecture/test_ports.py` fails if the old ports come back.
 */
const DEFAULT_API_PORT = 17171;

/** API base URL used when `PUBLIC_API_BASE` is not set. */
export const DEFAULT_API_BASE = `http://127.0.0.1:${DEFAULT_API_PORT}/api/v1`;

/** REST base URL, without a trailing slash. */
export const API_BASE = import.meta.env.PUBLIC_API_BASE ?? DEFAULT_API_BASE;

/**
 * `host:port` of the API, for building WebSocket URLs.
 *
 * A relative `PUBLIC_API_BASE` resolves against the page origin in the browser
 * and against the default base during SSR, so `new URL()` never throws.
 */
export const API_HOST = new URL(
  API_BASE,
  typeof window === "undefined" ? DEFAULT_API_BASE : window.location.href,
).host;

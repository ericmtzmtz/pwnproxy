interface ScanSourceHeaders {
  [key: string]: string;
}

interface ScanRequestSource {
  method: string;
  url: string;
  headers?: ScanSourceHeaders;
  body?: string | null;
}

export interface ScanTargetSource {
  method: string;
  url: string;
  headers?: ScanSourceHeaders;
  body?: string | null;
  /** Optional stored request (finding request_data) that overrides the source. */
  request_data?: ScanRequestSource | null;
}

const NO_BODY_METHODS = new Set(["GET", "HEAD"]);

function headerValue(headers: ScanSourceHeaders | undefined, name: string): string {
  if (!headers) return "";
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lower) return value || "";
  }
  return "";
}

/**
 * Build a `/scanners?...` URL preloading the New Scan form with a request
 * target. Uses `request_data` (finding payload-exact request) when present,
 * otherwise falls back to the source request's method/url/headers/body.
 */
export function buildScanTargetQuery(source: ScanTargetSource): string {
  const src = source.request_data ?? source;
  const method = (src.method || "GET").toUpperCase();
  const params = new URLSearchParams();

  if (src.url) params.set("url", src.url);
  params.set("method", method);

  const content_type = headerValue(src.headers, "content-type");
  if (content_type) params.set("content_type", content_type);

  const cookies = headerValue(src.headers, "cookie");
  if (cookies) params.set("cookies", cookies);

  if (!NO_BODY_METHODS.has(method) && src.body) params.set("body", src.body);

  return `/scanners?${params.toString()}`;
}

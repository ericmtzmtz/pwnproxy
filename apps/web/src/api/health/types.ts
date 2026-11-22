/** Shape of `GET /api/v1/health` (see `pwnproxy/transport/rest/health.py`). */

export interface HealthCheck {
  status: "ok" | "degraded" | "down" | string;
  message?: string;
  count?: number;
  active?: string[];
}

/** The proxy check also publishes the real listen port. */
export interface ProxyHealthCheck extends HealthCheck {
  port?: number;
}

export interface HealthResponse {
  status: string;
  version?: string | null;
  checks: {
    api?: HealthCheck;
    proxy?: ProxyHealthCheck;
    scanners?: HealthCheck;
    plugins?: HealthCheck;
    [key: string]: HealthCheck | ProxyHealthCheck | undefined;
  };
}

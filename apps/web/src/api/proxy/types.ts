export interface ProxyStatus {
  capture_enabled: boolean;
  running: boolean;
  host: string;
  port: number;
  ssl_insecure: boolean;
  upstream: string | null;
}

export interface FlowRecord {
  id: number;
  method: string;
  url: string;
  status_code: number | null;
  request_headers: Record<string, string>;
  response_headers: Record<string, string> | null;
  request_body: string | null;
  response_body: string | null;
  timestamp: string;
  duration_ms: number;
  tls: boolean;
  error: string | null;
}

export interface Finding {
  scanner: string;
  url: string;
  method: string;
  param_name: string;
  param_location: string;
  technique: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "confirmed" | "tentative" | "suspicious";
  payload: string;
  evidence: string;
  timestamp: string;
}

export interface FlowRecord {
  id: number;
  method: string;
  url: string;
  status_code: number;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  request_body: string | null;
  response_body: string | null;
  timestamp: string;
  duration_ms: number;
  tls: boolean;
  error: string | null;
}

export interface TriggerRequest {
  flow_id: number;
  scanners: string[];
}

export interface TriggerResponse {
  status: string;
  flow_id: number;
}

export interface FlowTriggerRequest {
  id: string;
  method: string;
  url: string;
  request_headers?: Record<string, string>;
  request_body?: string | null;
  status_code?: number | null;
  response_headers?: Record<string, string>;
  response_body?: string | null;
}

export interface FlowTriggerResponse {
  status: string;
  flow_id: string;
}

export interface RepeaterRequest {
  raw_request: string;
}

export interface RepeaterResponse {
  task_id: string;
  status_code: number;
  headers: Record<string, string>;
  body_preview: string;
  timing_ms: number;
}

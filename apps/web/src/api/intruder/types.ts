export interface IntruderRunRequest {
  raw_request: string;
  mode: "sniper" | "cluster_bomb";
  wordlist_path: string;
  concurrency?: number;
  max_results?: number;
}

export interface IntruderResult {
  request_id: number;
  payload: string;
  status_code: number;
  response_length: number;
  timing_ms: number;
  response_headers: Record<string, string>;
  response_body: string;
  error: string | null;
}

export interface IntruderRunResponse {
  attack_id: string;
  task_id: string;
  status: string;
  total: number;
}

export interface WordlistEntry {
  name: string;
  path: string;
  size_bytes: number;
  line_count: number;
}

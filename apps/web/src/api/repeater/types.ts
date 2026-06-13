export interface RepeaterRequest {
  raw_request: string;
  tab_id?: number;
}

export interface RepeaterResponse {
  task_id: string;
  status_code: number;
  headers: Record<string, string>;
  body_preview: string;
  timing_ms: number;
}

export interface RepeaterTab {
  id: number;
  name: string;
  raw_request: string;
  last_task_id?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateRepeaterTab {
  name?: string;
  raw_request?: string;
}

export interface UpdateRepeaterTab {
  name?: string;
  raw_request?: string;
  last_task_id?: string;
}

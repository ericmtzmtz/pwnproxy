export interface TaskSummary {
  id: string;
  type: string;
  status: string;
  progress: number;
  total: number;
  created_at: string;
  completed_at: string | null;
}

export interface TaskStatus {
  id: string;
  type: string;
  status: string;
  progress: number;
  total: number;
  config: Record<string, unknown>;
  result: Record<string, unknown> | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

/** One finding inside a `scan` task result (`ExportEngine.to_dicts()`). */
export interface ScanFinding {
  scanner: string;
  url: string;
  method: string;
  param_name: string;
  param_location: string;
  technique: string;
  severity: string;
  confidence: string;
  payload: string;
  evidence: string;
}

/** Result payload stored by `POST /repeater/send` (type `repeater`). */
export interface RepeaterTaskResult {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  duration_ms: number;
  error?: string;
}

export interface TaskListResponse {
  tasks: TaskSummary[];
  total: number;
}

/** Item of `GET /tasks?detail=true`: a summary plus `config` and `result`. */
export interface TaskSummaryDetail extends TaskSummary {
  config: Record<string, unknown>;
  result: Record<string, unknown> | null;
}

export interface TaskListDetailResponse {
  tasks: TaskSummaryDetail[];
  total: number;
}

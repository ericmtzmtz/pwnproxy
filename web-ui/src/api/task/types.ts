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

export interface TaskListResponse {
  tasks: TaskSummary[];
  total: number;
}

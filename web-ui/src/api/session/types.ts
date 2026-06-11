export interface SessionSummary {
  name: string;
  created_at: string | null;
  last_modified: string | null;
  active: boolean;
  last_active: boolean;
  request_count: number;
  finding_count: number;
}

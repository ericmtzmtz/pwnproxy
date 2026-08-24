export interface FindingRow {
  id: number;
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
  timestamp: string;
}

export type ReportAudience = "executive" | "technical" | "remediation";
export type ReportFormat = "md" | "html" | "pdf";

export interface ReportGenerateRequest {
  audience: ReportAudience;
  formats: ReportFormat[];
}

export interface ReportGenerateResponse {
  task_id: string;
}

export interface ReportResult extends Record<string, unknown> {
  phase?: string;
  files?: Record<string, string>;
  report_dir?: string;
  aggregates?: Record<string, unknown>;
  flagged_groups?: number;
  audience?: string;
  session?: string;
}

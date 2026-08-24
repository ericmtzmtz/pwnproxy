export interface RequestData {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
}

export type TriageVerdict = "true_positive" | "false_positive" | "uncertain";
export type TriageMethod = "heuristic" | "llm" | "human";

export interface Finding {
  id: number;
  scanner: string;
  url: string;
  method: string;
  param_name: string;
  param_location: string;
  severity: string;
  confidence: string;
  payload: string;
  evidence: string | null;
  technique: string;
  timestamp: string;
  request_data?: RequestData | null;
  triage_score?: number | null;
  triage_verdict?: TriageVerdict | null;
  triage_method?: TriageMethod | null;
  triage_reason?: string | null;
}

export interface PaginatedFindings {
  items: Finding[];
  total: number;
  page: number;
  per_page: number;
}

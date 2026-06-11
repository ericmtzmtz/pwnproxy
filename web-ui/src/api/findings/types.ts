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
}

export interface PaginatedFindings {
  items: Finding[];
  total: number;
  page: number;
  per_page: number;
}

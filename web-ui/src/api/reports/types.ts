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

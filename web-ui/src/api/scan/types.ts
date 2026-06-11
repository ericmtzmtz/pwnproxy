import { API_BASE } from "@/core";

export interface FindingItem {
  scanner: string;
  url: string;
  method: string;
  param_name: string;
  severity: string;
  confidence: string;
  payload: string;
  evidence: string;
}

export interface ScanTask {
  scan_id: string;
  status: "running" | "completed" | "failed";
  url: string;
  findings_count: number;
  findings: FindingItem[];
  error: string | null;
}

export interface LaunchResponse {
  scan_id: string;
  task_id: string;
  status: string;
}

export interface BurpImportResponse {
  status: string;
  imported: number;
  include_count: number;
  exclude_count: number;
}

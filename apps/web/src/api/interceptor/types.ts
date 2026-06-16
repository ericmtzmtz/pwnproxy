import { API_BASE } from "@/core";

export interface PendingFlow {
  id: string;
  method: string;
  url: string;
  host?: string;
  status_code: number | null;
  timestamp: string | null;
}

export interface InterceptStatus {
  enabled: boolean;
  pending_count: number;
}

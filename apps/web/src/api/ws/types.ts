export interface ScanStartedEvent {
  type: "scan.started";
  task_id: string;
  scanners: string;
  target: string;
  timestamp: string;
}

export interface ScanCompletedEvent {
  type: "scan.completed";
  task_id: string;
  findings_count: number;
  duration_ms: number;
  timestamp: string;
}

export type WebSocketEvent =
  | { type: "flow"; id: string; method: string; url: string; status_code: number }
  | { type: "finding"; scanner: string; url: string; severity: string; confidence: string }
  | ScanStartedEvent
  | ScanCompletedEvent;

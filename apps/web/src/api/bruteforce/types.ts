export interface BruteforceStartRequest {
  base_urls: string[];
  wordlist?: string | string[];
  extensions?: string[];
  status_filter?: number[];
  rate_limit?: number;
  concurrency?: number;
  max_requests?: number;
  detect_soft404?: boolean;
}

export interface BruteforceJob {
  id: number;
  type: string;
  status: string;
  config: string;
  stats: string;
  error: string | null;
  tenant_id: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface CrawlStatus {
  running: boolean;
  pid: number | null;
  event_port: number;
  feed_port: number;
  active_jobs: BruteforceJob[];
}

export interface WordlistInfo {
  name: string;
  entries: number;
}

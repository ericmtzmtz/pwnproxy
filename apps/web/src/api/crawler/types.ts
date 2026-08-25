export interface DiscoveredUrl {
  id: number;
  url: string;
  base_url: string;
  method: string;
  source: string;
  timestamp: string;
}

export interface PaginatedDiscoveredUrls {
  items: DiscoveredUrl[];
  total: number;
  page: number;
  per_page: number;
}

export interface CrawlStartRequest {
  seeds: string[];
  depth?: number;
  rate_limit?: number;
  concurrency?: number;
  max_urls?: number;
  respect_robots?: boolean;
  include_discovered?: boolean;
  scan_while_crawl?: boolean;
}

export interface CrawlJob {
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
  active_jobs: CrawlJob[];
}

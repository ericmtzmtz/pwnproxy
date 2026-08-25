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

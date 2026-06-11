export interface PluginInfo {
  name: string;
  version: string;
  author: string;
  category: string;
  disabled: boolean;
}

export interface PluginListResponse {
  plugins: PluginInfo[];
  error?: string;
}

export interface ToggleResponse {
  status: string;
  name: string;
}

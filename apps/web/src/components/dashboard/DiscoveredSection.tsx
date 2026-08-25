import { useEffect, useState } from "preact/hooks";
import { listDiscoveredUrls } from "@/api/crawler/calls";
import { formatTimeOnly } from "@/utils/formatTimestamp";
import type { DiscoveredUrl } from "@/api/crawler/types";

const SOURCE_BADGE: Record<string, string> = {
  a: "bg-blue-900/40 text-blue-400",
  form: "bg-purple-900/40 text-purple-400",
  script: "bg-yellow-900/40 text-yellow-400",
  js: "bg-amber-900/40 text-amber-400",
  img: "bg-cyan-900/40 text-cyan-400",
  iframe: "bg-red-900/40 text-red-400",
  link: "bg-teal-900/40 text-teal-400",
  source: "bg-pink-900/40 text-pink-400",
  area: "bg-green-900/40 text-green-400",
  location: "bg-orange-900/40 text-orange-400",
};

function SourceBadge({ source }: { source: string }) {
  const cls = SOURCE_BADGE[source] ?? "bg-neutral-800 text-neutral-400";
  return (
    <span class={`inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold ${cls}`}>
      {source}
    </span>
  );
}

function truncateUrl(url: string, max = 60): string {
  if (url.length <= max) return url;
  return url.slice(0, max) + "…";
}

export function DiscoveredSection() {
  const [urls, setUrls] = useState<DiscoveredUrl[]>([]);
  const [total, setTotal] = useState(0);
  const [liveIds, setLiveIds] = useState<Set<number>>(new Set());

  useEffect(() => {
    listDiscoveredUrls(1, 50)
      .then((res) => {
        setUrls(res.items);
        setTotal(res.total);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const handler = (e: CustomEvent) => {
      const d = e.detail;
      if (!d?.id || !d?.url) return;
      if (urls.some((u) => u.id === d.id)) return;
      const newItem: DiscoveredUrl = {
        id: d.id,
        url: d.url,
        base_url: d.base_url ?? "",
        method: d.method ?? "GET",
        source: d.source ?? "",
        timestamp: d.timestamp ?? new Date().toISOString(),
      };
      setUrls((prev) => [newItem, ...prev].slice(0, 50));
      setTotal((t) => t + 1);
      setLiveIds((prev) => new Set(prev).add(d.id));
    };
    window.addEventListener("pwnproxy-crawler-url" as any, handler as EventListener);
    return () => window.removeEventListener("pwnproxy-crawler-url" as any, handler as EventListener);
  }, [urls]);

  return (
    <div>
      <div class="mb-3 flex items-center justify-between">
        <h2 class="text-sm font-semibold text-neutral-200">Discovered URLs</h2>
        <span class="text-xs text-neutral-500">{total} total</span>
      </div>
      {urls.length === 0 ? (
        <p class="text-xs text-neutral-600">No URLs discovered yet. Traffic passing through the proxy will be scanned for endpoints.</p>
      ) : (
        <div class="max-h-64 space-y-1 overflow-y-auto pr-1">
          {urls.map((u) => (
            <div
              key={u.id}
              class={`flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs ${
                liveIds.has(u.id)
                  ? "border-green-900/40 bg-green-950/20"
                  : "border-neutral-800 bg-neutral-950"
              }`}
            >
              <span class="w-14 shrink-0 text-neutral-500">{formatTimeOnly(u.timestamp)}</span>
              <span class="w-10 shrink-0 font-semibold uppercase text-neutral-400">{u.method}</span>
              <SourceBadge source={u.source} />
              <span class="min-w-0 truncate text-neutral-300" title={u.url}>
                {truncateUrl(u.url)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

import { useEffect, useState, useRef } from "preact/hooks";
import { startCrawl, stopCrawl, getCrawlStatus, listDiscoveredUrls } from "@/api/crawler/calls";
import { DiscoveredSection } from "@/components/dashboard/DiscoveredSection";
import type { CrawlJob, CrawlStartRequest } from "@/api/crawler/types";

const STATUS_COLORS: Record<string, string> = {
  queued: "bg-yellow-900/40 text-yellow-400",
  running: "bg-green-900/40 text-green-400",
  completed: "bg-blue-900/40 text-blue-400",
  failed: "bg-red-900/40 text-red-400",
  stopped: "bg-neutral-700/40 text-neutral-400",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLORS[status] ?? "bg-neutral-800 text-neutral-400";
  return (
    <span class={`inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold ${cls}`}>
      {status}
    </span>
  );
}

export function CrawlerPage() {
  const [seeds, setSeeds] = useState("");
  const [depth, setDepth] = useState(3);
  const [rateLimit, setRateLimit] = useState(10);
  const [concurrency, setConcurrency] = useState(5);
  const [maxUrls, setMaxUrls] = useState(1000);
  const [respectRobots, setRespectRobots] = useState(false);
  const [includeDiscovered, setIncludeDiscovered] = useState(false);
  const [scanWhileCrawl, setScanWhileCrawl] = useState(false);

  const [activeJob, setActiveJob] = useState<CrawlJob | null>(null);
  const [stats, setStats] = useState({ fetched: 0, queued: 0, discovered: 0, errors: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    pollStatus();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  async function pollStatus() {
    try {
      const status = await getCrawlStatus();
      const jobs = status.active_jobs ?? [];
      const running = jobs.find((j: CrawlJob) => j.status === "running" || j.status === "queued");
      if (running) {
        setActiveJob(running);
        try {
          const parsed = JSON.parse(running.stats || "{}");
          setStats(parsed);
        } catch {}
        setLoading(true);
        if (!pollRef.current) {
          pollRef.current = window.setInterval(pollStatus, 2000);
        }
      } else {
        if (activeJob && activeJob.status === "running") {
          // Job just finished — refresh final stats
          const finishedJobs = (await getCrawlStatus()).active_jobs ?? [];
          const finished = finishedJobs.find((j: CrawlJob) => j.id === activeJob.id);
          if (finished) {
            setActiveJob(finished);
            try { setStats(JSON.parse(finished.stats || "{}")); } catch {}
          }
        }
        setActiveJob(null);
        setLoading(false);
        if (pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
      }
    } catch {
      setActiveJob(null);
      setLoading(false);
    }
  }

  async function handleStart() {
    const seedList = seeds.split("\n").map(s => s.trim()).filter(Boolean);
    if (seedList.length === 0) {
      setError("At least one seed URL is required");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const req: CrawlStartRequest = {
        seeds: seedList,
        depth,
        rate_limit: rateLimit,
        concurrency,
        max_urls: maxUrls,
        respect_robots: respectRobots,
        include_discovered: includeDiscovered,
        scan_while_crawl: scanWhileCrawl,
      };
      await startCrawl(req);
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Crawl started", message: "Active crawl job launched", severity: "success" },
      }));
      pollStatus();
    } catch (err: any) {
      setError(err.message ?? "Failed to start crawl");
      setLoading(false);
    }
  }

  async function handleStop() {
    try {
      await stopCrawl();
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Crawl stopped", message: "Active crawl job stopped", severity: "info" },
      }));
      pollStatus();
    } catch (err: any) {
      setError(err.message ?? "Failed to stop crawl");
    }
  }

  return (
    <div class="space-y-6">
      <div>
        <h1 class="text-xl font-bold text-neutral-50">Active Crawler</h1>
        <p class="mt-0.5 text-sm text-neutral-400">Crawl target sites from seed URLs and discover endpoints</p>
      </div>

      {/* Crawl form */}
      <div class="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
        <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-neutral-400">Seed URLs (one per line)</label>
            <textarea
              value={seeds}
              onInput={(e) => setSeeds((e.target as HTMLTextAreaElement).value)}
              rows={4}
              placeholder={"https://target.com/\nhttps://target.com/admin"}
              class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-xs text-neutral-100 placeholder-neutral-500 focus:border-primary-500 focus:outline-none"
              disabled={loading}
            />
          </div>
          <div class="space-y-3">
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Depth</label>
                <input type="number" value={depth} min={1} max={10}
                  onInput={(e) => setDepth(Number((e.target as HTMLInputElement).value))}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Rate limit (req/s)</label>
                <input type="number" value={rateLimit} min={1} max={100}
                  onInput={(e) => setRateLimit(Number((e.target as HTMLInputElement).value))}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Concurrency</label>
                <input type="number" value={concurrency} min={1} max={50}
                  onInput={(e) => setConcurrency(Number((e.target as HTMLInputElement).value))}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Max URLs</label>
                <input type="number" value={maxUrls} min={1} max={50000}
                  onInput={(e) => setMaxUrls(Number((e.target as HTMLInputElement).value))}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
            </div>
            <div class="flex flex-wrap gap-4 text-xs text-neutral-400">
              <label class="flex items-center gap-1.5">
                <input type="checkbox" checked={respectRobots} onChange={(e) => setRespectRobots((e.target as HTMLInputElement).checked)} disabled={loading}
                  class="rounded border-neutral-600 bg-neutral-800 text-primary-500 focus:ring-primary-500" />
                Respect robots.txt
              </label>
              <label class="flex items-center gap-1.5">
                <input type="checkbox" checked={includeDiscovered} onChange={(e) => setIncludeDiscovered((e.target as HTMLInputElement).checked)} disabled={loading}
                  class="rounded border-neutral-600 bg-neutral-800 text-primary-500 focus:ring-primary-500" />
                Include discovered
              </label>
              <label class="flex items-center gap-1.5">
                <input type="checkbox" checked={scanWhileCrawl} onChange={(e) => setScanWhileCrawl((e.target as HTMLInputElement).checked)} disabled={loading}
                  class="rounded border-neutral-600 bg-neutral-800 text-primary-500 focus:ring-primary-500" />
                Scan while crawling
              </label>
            </div>
          </div>
        </div>

        {error && (
          <div class="mt-3 rounded-md border border-red-800 bg-red-900/20 px-3 py-2 text-xs text-red-400">{error}</div>
        )}

        <div class="mt-4 flex items-center gap-3">
          {!loading ? (
            <button onClick={handleStart}
              class="rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400">
              Start Crawl
            </button>
          ) : (
            <button onClick={handleStop}
              class="rounded-md border border-danger-800 bg-danger-900/20 px-4 py-2 text-sm font-medium text-danger-400 transition-colors hover:bg-danger-900/40">
              Stop
            </button>
          )}
          {activeJob && (
            <div class="flex items-center gap-2 text-xs text-neutral-500">
              <StatusBadge status={activeJob.status} />
              <span>Job #{activeJob.id}</span>
            </div>
          )}
        </div>
      </div>

      {/* Stats */}
      {loading && (
        <div class="grid grid-cols-4 gap-3">
          {[
            { label: "Fetched", value: stats.fetched },
            { label: "Queued", value: stats.queued },
            { label: "Discovered", value: stats.discovered },
            { label: "Errors", value: stats.errors },
          ].map(({ label, value }) => (
            <div key={label} class="rounded-lg border border-neutral-800 bg-neutral-950 px-3 py-2 text-center">
              <p class="text-lg font-bold text-neutral-50">{value}</p>
              <p class="text-[10px] text-neutral-500">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Discovered URLs */}
      <div class="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
        <DiscoveredSection />
      </div>
    </div>
  );
}

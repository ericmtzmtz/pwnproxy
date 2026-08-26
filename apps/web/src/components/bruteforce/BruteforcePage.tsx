import { useEffect, useState, useRef } from "preact/hooks";
import { startBruteforce, stopBruteforce, getBruteforceStatus, listWordlists } from "@/api/bruteforce/calls";
import { DiscoveredSection } from "@/components/dashboard/DiscoveredSection";
import type { BruteforceJob, BruteforceStartRequest, WordlistInfo } from "@/api/bruteforce/types";

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

export function BruteforcePage() {
  const [baseUrls, setBaseUrls] = useState("");
  const [wordlist, setWordlist] = useState("medium");
  const [extensions, setExtensions] = useState("");
  const [statusFilter, setStatusFilter] = useState("200,204,301,302,307,401,403");
  const [rateLimit, setRateLimit] = useState(20);
  const [concurrency, setConcurrency] = useState(10);
  const [maxRequests, setMaxRequests] = useState(100000);
  const [detectSoft404, setDetectSoft404] = useState(true);

  const [activeJob, setActiveJob] = useState<BruteforceJob | null>(null);
  const [stats, setStats] = useState({ probed: 0, found: 0, errors: 0, soft404_filtered: 0, total_planned: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [wordlists, setWordlists] = useState<WordlistInfo[]>([]);
  const pollRef = useRef<number | null>(null);

  const baseCount = baseUrls.split("\n").map(s => s.trim()).filter(Boolean).length;
  const extCount = extensions.split(",").map(s => s.trim()).filter(Boolean).length;
  const wlEntries = wordlists.find(w => w.name === wordlist)?.entries ?? 0;
  const estimatedRequests = wlEntries * (1 + extCount) * baseCount;

  useEffect(() => {
    listWordlists()
      .then((res) => setWordlists(res.wordlists))
      .catch(() => {});
    pollStatus();
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  async function pollStatus() {
    try {
      const status = await getBruteforceStatus();
      const jobs = status.active_jobs ?? [];
      const running = jobs.find((j: BruteforceJob) => (j.type === "bruteforce") && (j.status === "running" || j.status === "queued"));
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
    const urlList = baseUrls.split("\n").map(s => s.trim()).filter(Boolean);
    if (urlList.length === 0) {
      setError("At least one base URL is required");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const req: BruteforceStartRequest = {
        base_urls: urlList,
        wordlist,
        extensions: extensions.split(",").map(s => s.trim()).filter(Boolean),
        status_filter: statusFilter.split(",").map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n)),
        rate_limit: rateLimit,
        concurrency,
        max_requests: maxRequests,
        detect_soft404: detectSoft404,
      };
      const res = await startBruteforce(req);
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Bruteforce started", message: `Est. ${res.total_estimated.toLocaleString()} requests`, severity: "success" },
      }));
      pollStatus();
    } catch (err: any) {
      setError(err.message ?? "Failed to start bruteforce");
      setLoading(false);
    }
  }

  async function handleStop() {
    try {
      await stopBruteforce();
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Bruteforce stopped", message: "Active bruteforce job stopped", severity: "info" },
      }));
      pollStatus();
    } catch (err: any) {
      setError(err.message ?? "Failed to stop bruteforce");
    }
  }

  return (
    <div class="space-y-6">
      <div>
        <h1 class="text-xl font-bold text-neutral-50">Directory Bruteforce</h1>
        <p class="mt-0.5 text-sm text-neutral-400">Discover hidden paths and endpoints using wordlist-based directory brute-forcing</p>
      </div>

      {/* Bruteforce form */}
      <div class="rounded-lg border border-neutral-700 bg-neutral-900 p-4">
        <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <label class="mb-1 block text-xs font-medium text-neutral-400">Base URLs (one per line)</label>
            <textarea
              value={baseUrls}
              onInput={(e) => setBaseUrls((e.target as HTMLTextAreaElement).value)}
              rows={4}
              placeholder={"https://target.com/\nhttps://target.com/api"}
              class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-xs text-neutral-100 placeholder-neutral-500 focus:border-primary-500 focus:outline-none"
              disabled={loading}
            />
          </div>
          <div class="space-y-3">
            <div>
              <label class="mb-1 block text-xs font-medium text-neutral-400">Wordlist</label>
              <select
                value={wordlist}
                onChange={(e) => setWordlist((e.target as HTMLSelectElement).value)}
                class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none"
                disabled={loading}
              >
                {wordlists.map((wl) => (
                  <option key={wl.name} value={wl.name}>{wl.name} ({wl.entries.toLocaleString()} entries)</option>
                ))}
              </select>
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-neutral-400">Extensions (comma-separated, e.g. .php,.html)</label>
              <input type="text" value={extensions}
                onInput={(e) => setExtensions((e.target as HTMLInputElement).value)}
                placeholder=".php,.html,.txt"
                class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 placeholder-neutral-500 focus:border-primary-500 focus:outline-none"
                disabled={loading} />
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Rate limit (req/s)</label>
                <input type="number" value={rateLimit} min={1} max={200}
                  onInput={(e) => setRateLimit(Number((e.target as HTMLInputElement).value))}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Concurrency</label>
                <input type="number" value={concurrency} min={1} max={100}
                  onInput={(e) => setConcurrency(Number((e.target as HTMLInputElement).value))}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Max requests</label>
                <input type="number" value={maxRequests} min={1} max={2000000}
                  onInput={(e) => setMaxRequests(Number((e.target as HTMLInputElement).value))}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
              <div>
                <label class="mb-1 block text-xs font-medium text-neutral-400">Status filter (comma-separated)</label>
                <input type="text" value={statusFilter}
                  onInput={(e) => setStatusFilter((e.target as HTMLInputElement).value)}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-2 py-1.5 text-xs text-neutral-100 focus:border-primary-500 focus:outline-none" disabled={loading} />
              </div>
            </div>
            <div class="flex items-center gap-1.5 text-xs text-neutral-400">
              <label class="flex items-center gap-1.5">
                <input type="checkbox" checked={detectSoft404} onChange={(e) => setDetectSoft404((e.target as HTMLInputElement).checked)} disabled={loading}
                  class="rounded border-neutral-600 bg-neutral-800 text-primary-500 focus:ring-primary-500" />
                Detect soft-404
              </label>
            </div>
          </div>
        </div>

        {error && (
          <div class="mt-3 rounded-md border border-red-800 bg-red-900/20 px-3 py-2 text-xs text-red-400">{error}</div>
        )}

        {!loading && estimatedRequests > 0 && (
          <p class="mt-3 text-xs text-neutral-500">
            Estimated requests: <span class="font-semibold text-neutral-300">{estimatedRequests.toLocaleString()}</span>
          </p>
        )}

        <div class="mt-4 flex items-center gap-3">
          {!loading ? (
            <button onClick={handleStart}
              class="rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400">
              Start Bruteforce
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
            { label: "Probed", value: stats.probed },
            { label: "Hits", value: stats.found },
            { label: "Soft-404 filtered", value: stats.soft404_filtered },
            { label: "Errors", value: stats.errors },
          ].map(({ label, value }) => (
            <div key={label} class="rounded-lg border border-neutral-800 bg-neutral-950 px-3 py-2 text-center">
              <p class="text-lg font-bold text-neutral-50">{value ?? 0}</p>
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

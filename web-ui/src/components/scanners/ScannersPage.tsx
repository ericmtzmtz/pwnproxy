import { useEffect, useState } from "preact/hooks";
import { launchScan } from "@/api/scan/calls";
import { listPlugins } from "@/api/plugins/calls";
import { TaskPoller } from "@/components/task/TaskPoller";

const SCANNER_NAMES = ["sqli", "xss", "lfi", "xxe", "ssrf"] as const;

export function ScannersPage() {
  const [targetUrl, setTargetUrl] = useState("https://httpbin.org/get");
  const [selectedScanner, setSelectedScanner] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanTaskId, setScanTaskId] = useState<string | null>(null);
  const [disabledPlugins, setDisabledPlugins] = useState<Set<string>>(new Set());

  useEffect(() => {
    listPlugins()
      .then((data) => {
        const disabled = new Set(data.plugins.filter((p) => p.disabled).map((p) => p.name));
        setDisabledPlugins(disabled);
      })
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    const url = targetUrl.trim();
    if (!url) return;

    setScanning(true);
    setScanTaskId(null);

    try {
      const { scan_id } = await launchScan(url, selectedScanner);
      setScanTaskId(scan_id);
    } catch (err: any) {
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Scan error", message: err.message ?? "Unknown error", severity: "error" },
      }));
      setScanning(false);
    }
  };

  const handleComplete = () => {
    setScanning(false);
  };

  return (
    <div>
      <div class="mb-6">
        <h1 class="text-xl font-bold text-neutral-50">Scanners</h1>
        <p class="mt-0.5 text-sm text-neutral-400">Run vulnerability scans against targets</p>
      </div>

      <div class="rounded-lg border border-neutral-800 bg-neutral-950 p-4">
        <h3 class="mb-3 text-sm font-semibold text-neutral-200">New Scan</h3>
        <form onSubmit={handleSubmit} class="flex items-end gap-3">
          <div class="flex-1">
            <label for="target-url" class="mb-1 block text-xs font-medium text-neutral-400">Target URL</label>
            <input
              id="target-url"
              type="url"
              value={targetUrl}
              onInput={(e) => setTargetUrl((e.target as HTMLInputElement).value)}
              placeholder="https://example.com"
              class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 placeholder-neutral-500 transition-colors focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
            />
          </div>
          <div>
            <label for="scanner-select" class="mb-1 block text-xs font-medium text-neutral-400">Scanners</label>
            <select
              id="scanner-select"
              value={selectedScanner}
              onChange={(e) => setSelectedScanner((e.target as HTMLSelectElement).value)}
              class="rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 transition-colors focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
            >
              <option value="">All scanners</option>
              {SCANNER_NAMES.map((n) => (
                <option value={n} disabled={disabledPlugins.has(n)}>{n.toUpperCase()} only</option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            disabled={scanning}
            class="inline-flex items-center gap-2 rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
          >
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            {scanning ? "Scanning..." : "Scan"}
          </button>
        </form>
      </div>

      <div class="mt-4 grid grid-cols-5 gap-3">
        {SCANNER_NAMES.map((name) => {
          const off = disabledPlugins.has(name);
          return (
            <div class={`rounded-lg border p-3 ${off ? "border-neutral-800 bg-neutral-950" : "border-neutral-800 bg-neutral-900"}`}>
              <div class="flex items-center justify-between">
                <span class={`text-xs font-semibold uppercase tracking-wider ${off ? "text-neutral-600" : "text-neutral-400"}`}>{name}</span>
                <span class={`inline-flex h-2 w-2 rounded-full ${off ? "bg-neutral-700" : "bg-success-500"}`} title={off ? "Disabled" : "Active"} />
              </div>
              <p class={`mt-1 text-[11px] ${off ? "text-neutral-600" : "text-neutral-500"}`}>{off ? "Disabled" : "Ready"}</p>
            </div>
          );
        })}
      </div>

      <div class="mt-6">
        <h2 class="mb-3 text-sm font-semibold text-neutral-200">Results</h2>

        {scanTaskId && (
          <TaskPoller taskId={scanTaskId} onComplete={handleComplete} />
        )}

        {!scanTaskId && !scanning && (
          <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-neutral-800 py-16 text-neutral-600">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="mb-3 h-10 w-10"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
            <p class="text-sm">No scans yet</p>
            <p class="mt-1 text-xs">Enter a target URL and click Scan</p>
          </div>
        )}
      </div>
    </div>
  );
}

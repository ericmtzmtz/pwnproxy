import { useEffect, useRef, useState } from "preact/hooks";
import { createTab } from "@/api/repeater/calls";
import { launchScan } from "@/api/scan/calls";
import { listPlugins } from "@/api/plugins/calls";
import { PluginToggle } from "@/components/plugins/PluginToggle";
import { listTasks, pollTask, cancelTask, deleteTask } from "@/api/task/calls";
import type { TaskStatus, TaskSummary } from "@/api/task/types";
import { useWebSocket } from "@/hooks/useWebSocket";

const SCANNER_NAMES = ["sqli", "xss", "lfi", "xxe", "ssrf"] as const;
const PER_PAGE = 10;
const POLL_INTERVAL = 2000;

const SCANNER_BADGES: Record<string, string> = {
  All: "bg-neutral-700 text-neutral-200",
  sqli: "bg-red-900/60 text-red-300",
  xss: "bg-orange-900/60 text-orange-300",
  lfi: "bg-yellow-900/60 text-yellow-300",
  xxe: "bg-purple-900/60 text-purple-300",
  ssrf: "bg-cyan-900/60 text-cyan-300",
};

function badgeClass(scanner: string): string {
  const key = scanner.toLowerCase();
  return SCANNER_BADGES[key] ?? SCANNER_BADGES.All;
}

const WS_HOST = import.meta.env.PUBLIC_API_BASE
  ? new URL(import.meta.env.PUBLIC_API_BASE).host
  : "127.0.0.1:8000";

export function ScannersPage() {
  const [targetUrl, setTargetUrl] = useState("https://httpbin.org/get");
  const [selectedScanner, setSelectedScanner] = useState("");
  const [scanning, setScanning] = useState(false);
  const [disabledPlugins, setDisabledPlugins] = useState<Set<string>>(new Set());
  const [history, setHistory] = useState<TaskStatus[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const pollTimers = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());

  useWebSocket({
    url: `ws://${WS_HOST}/ws/events`,
    onMessage(msg) {
      if (msg.type === "scan.started") {
        window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
          detail: { title: "Scan started", message: msg.target as string, severity: "info" },
        }));
      } else if (msg.type === "scan.completed") {
        window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
          detail: {
            title: "Scan completed",
            message: `${(msg as any).findings_count ?? 0} findings`,
            severity: (msg as any).findings_count > 0 ? "warning" : "success",
          },
        }));
      }
    },
  });

  function upsertHistory(task: TaskStatus) {
    setHistory((prev) => {
      const idx = prev.findIndex((t) => t.id === task.id);
      if (idx >= 0) {
        const copy = [...prev];
        copy[idx] = task;
        return copy;
      }
      return [task, ...prev];
    });
  }

  function startBackgroundPoll(taskId: string) {
    if (pollTimers.current.has(taskId)) return;
    const timer = setInterval(async () => {
      try {
        const task = await pollTask(taskId);
        upsertHistory(task);
        if (task.status === "completed" || task.status === "failed" || task.status === "cancelled") {
          clearInterval(timer);
          pollTimers.current.delete(taskId);
          if (task.type === "scan") {
            const findings = (task.result?.findings as any[]) ?? [];
            window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
              detail: {
                title: `Scan ${task.status}`,
                message: findings.length > 0 ? `${findings.length} finding${findings.length > 1 ? "s" : ""}` : "No vulnerabilities found",
                severity: findings.length > 0 ? "warning" : "success",
              },
            }));
          }
        }
      } catch {
        clearInterval(timer);
        pollTimers.current.delete(taskId);
      }
    }, POLL_INTERVAL);
    pollTimers.current.set(taskId, timer);
  }

  useEffect(() => {
    return () => {
      pollTimers.current.forEach((t) => clearInterval(t));
      pollTimers.current.clear();
    };
  }, []);

  useEffect(() => {
    listPlugins()
      .then((data) => {
        const disabled = new Set(data.plugins.filter((p) => p.disabled).map((p) => p.name));
        setDisabledPlugins(disabled);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const { tasks } = await listTasks("scan");
        const details = await Promise.all(
          tasks.map((t: TaskSummary) => pollTask(t.id).catch(() => null)),
        );
        setHistory(details.filter(Boolean) as TaskStatus[]);
        // Restart background polling for still-running tasks
        for (const t of details) {
          if (t && t.status === "running") startBackgroundPoll(t.id);
        }
      } catch {}
    })();
  }, []);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    const url = targetUrl.trim();
    if (!url) return;
    setScanning(true);
    try {
      const { scan_id } = await launchScan(url, selectedScanner);
      const placeholder = {
        id: scan_id, status: "running", type: "scan",
        progress: 0, total: 0, config: { url, scanners: selectedScanner || "All" },
        result: null, error: null,
        created_at: new Date().toISOString(), completed_at: null,
      } as TaskStatus;
      upsertHistory(placeholder);
      startBackgroundPoll(scan_id);
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Scan started", message: url, severity: "info" },
      }));
    } catch (err: any) {
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Scan error", message: err.message ?? "Unknown error", severity: "error" },
      }));
    } finally {
      setScanning(false);
    }
  };

  function toggleExpand(id: string) {
    setExpandedId((prev) => (prev === id ? null : id));
  }

  async function handleDelete(id: string, e: MouseEvent) {
    e.stopPropagation();
    try {
      await deleteTask(id);
    } catch {}
    removeFromState(id);
    window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
      detail: { title: "Scan deleted", message: "Task removed from database", severity: "info" },
    }));
  }

  function removeFromState(id: string) {
    setHistory((prev) => prev.filter((t) => t.id !== id));
    const t = pollTimers.current.get(id);
    if (t) { clearInterval(t); pollTimers.current.delete(id); }
  }

  const totalPages = Math.max(1, Math.ceil(history.length / PER_PAGE));
  const safePage = Math.min(page, totalPages - 1);
  const paged = history.slice(safePage * PER_PAGE, (safePage + 1) * PER_PAGE);

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
            class="inline-flex items-center justify-center gap-2 rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
          >
            {scanning ? (
              <svg class="spinner h-4 w-4 border-2 border-white border-t-transparent" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-4 w-4"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            )}
            {scanning ? "Scanning..." : "Scan"}
          </button>
        </form>
      </div>

      <div class="mt-4 grid grid-cols-5 gap-3">
        {SCANNER_NAMES.map((name) => (
          <PluginToggle
            key={name}
            name={name}
            disabled={disabledPlugins.has(name)}
            onToggle={(n, d) => {
              setDisabledPlugins((prev) => {
                const next = new Set(prev);
                if (d) next.add(n);
                else next.delete(n);
                return next;
              });
            }}
          />
        ))}
      </div>

      {/* Scan history */}
      <div class="mt-6">
        <h2 class="mb-3 text-sm font-semibold text-neutral-200">Scan History ({history.length})</h2>

        {history.length === 0 && (
          <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-neutral-800 py-16 text-neutral-600">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="mb-3 h-10 w-10"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
            <p class="text-sm">No scans yet</p>
            <p class="mt-1 text-xs">Enter a target URL and click Scan</p>
          </div>
        )}

        {history.length > 0 && (
          <>
            <div class="space-y-3">
              {paged.map((task) => {
                const completed = task.status === "completed";
                const cancelled = task.status === "cancelled";
                const findings = (task.result?.findings as any[]) ?? [];
                const isOpen = expandedId === task.id;
                const ts = new Date(task.created_at);
                const label = ts.toLocaleString();
                const cfgUrl = (task.config?.url as string) ?? "";
                const cfgScanners = (task.config?.scanners as string) || "All";
                return (
                  <div class="group rounded-lg border border-neutral-800 bg-neutral-950">
                    <button
                      onClick={() => toggleExpand(task.id)}
                      class="flex w-full items-center justify-between px-4 py-3 text-left transition-colors hover:bg-neutral-900/50"
                    >
                      <div class="flex items-center gap-3">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                          class={`h-4 w-4 text-neutral-500 transition-transform ${isOpen ? "rotate-90" : ""}`}
                        ><polyline points="9 18 15 12 9 6"/></svg>
                        <span class="text-sm font-medium text-neutral-200">Scan #{task.id.slice(0, 8)}</span>
                        <span class="max-w-[200px] truncate text-xs text-neutral-500" title={cfgUrl}>{cfgUrl}</span>
                        <span class="text-xs text-neutral-500">{label}</span>
                      </div>
                      <div class="flex items-center gap-3">
                        <span class={`hidden rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider sm:inline ${badgeClass(cfgScanners)}`}>
                          {cfgScanners}
                        </span>
                        {!completed && !cancelled ? (
                          <>
                            <span class="inline-flex items-center gap-1.5 rounded-full bg-blue-900/40 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-blue-400">
                              <span class="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-blue-400" />
                              Running
                            </span>
                            <button
                              onClick={async (e) => {
                                e.stopPropagation();
                                try {
                                  await cancelTask(task.id);
                                } catch {}
                                setHistory((prev) => prev.map((t) =>
                                  t.id === task.id ? { ...t, status: "cancelled", completed_at: new Date().toISOString() } : t
                                ));
                                const t = pollTimers.current.get(task.id);
                                if (t) { clearInterval(t); pollTimers.current.delete(task.id); }
                                window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
                                  detail: { title: "Scan cancelled", message: "", severity: "info" },
                                }));
                              }}
                              class="inline-flex items-center gap-1 rounded bg-red-900/40 px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-red-400 transition-colors hover:bg-red-800/60"
                              title="Stop scan"
                            >
                              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-3 w-3"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>
                              Stop
                            </button>
                          </>
                        ) : (
                          <span class={`text-xs ${cancelled ? "text-neutral-500" : findings.length > 0 ? "text-orange-400" : "text-success-500"}`}>
                            {cancelled ? "Cancelled" : findings.length > 0 ? `${findings.length} finding${findings.length > 1 ? "s" : ""}` : "Clean"}
                          </span>
                        )}
                        <span class="text-xs text-neutral-500">{task.completed_at ? `${Math.round((new Date(task.completed_at).getTime() - new Date(task.created_at).getTime()) / 1000)}s` : "-"}</span>
                        <button
                          onClick={(e) => handleDelete(task.id, e)}
                          class="rounded p-1 text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-red-400"
                          title="Delete scan"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="h-4 w-4"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a4 4 0 0 1 2 2v2"/></svg>
                        </button>
                      </div>
                    </button>
                    {isOpen && (
                      <div class="border-t border-neutral-800 px-4 py-3">
                        {findings.length === 0 ? (
                          <p class="text-xs text-neutral-500">No vulnerabilities found</p>
                        ) : (
                          <div class="overflow-x-auto rounded-md border border-neutral-800">
                            <table class="w-full text-xs">
                              <thead>
                                <tr class="border-b border-neutral-800 bg-neutral-900">
                                  <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400">Severity</th>
                                  <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400">Scanner</th>
                                  <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400">URL</th>
                                  <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400">Param</th>
                                  <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400">Confidence</th>
                                  <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400">Payload</th>
                                   <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400">Action</th>
                                </tr>
                              </thead>
                              <tbody class="divide-y divide-neutral-800">
                                {findings.map((f: any, i: number) => (
                                  <tr key={i} class="bg-neutral-950 hover:bg-neutral-900/50">
                                    <td class={`px-3 py-2 font-semibold ${sevColor(f.severity)}`}>{f.severity}</td>
                                    <td class="px-3 py-2 font-mono uppercase text-neutral-300">{f.scanner}</td>
                                    <td class="max-w-[300px] truncate px-3 py-2 text-neutral-400" title={f.url}>{f.url}</td>
                                    <td class="px-3 py-2 font-mono text-neutral-300">{f.param_name || "-"}</td>
                                    <td class="px-3 py-2">
                                      <span class={`inline-flex items-center rounded-full ${f.confidence === "confirmed" ? "bg-red-900/40 text-red-400" : "bg-yellow-900/40 text-yellow-400"} px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider`}>
                                        {f.confidence}
                                      </span>
                                    </td>
                                    <td class="max-w-[200px] truncate px-3 py-2 font-mono text-neutral-400" title={f.payload}>{f.payload || "-"}</td>
                                        <td class="px-3 py-2">
                                          <button
                                            onClick={async () => {
                                              try {
                                                let rawRequest: string;
                                                let tabName: string;
                                                if (f.request_data?.url) {
                                                  // Payload-exact: stored request with the triggering payload
                                                  const rd = f.request_data;
                                                  const u = new URL(rd.url);
                                                  const path = u.pathname + u.search;
                                                  const headers = Object.entries(rd.headers || {})
                                                    .map(([k, v]) => `${k}: ${v}`)
                                                    .join("\n");
                                                  const body = rd.body ? `\n\n${rd.body}` : "\n\n";
                                                  rawRequest = `${rd.method || "GET"} ${path} HTTP/1.1\n${headers}${body}`;
                                                  tabName = `${rd.method || "GET"} ${path.slice(0, 30)}`;
                                                } else {
                                                  const u = new URL(f.url);
                                                  const path = u.pathname + u.search;
                                                  const method = f.method || "GET";
                                                  // Rebuild with the finding payload when it was a param/header injection
                                                  let headers = `Host: ${u.host}\nUser-Agent: pwnproxy-repeater/0.1\nAccept: */*`;
                                                  if (f.param_location === "header" && f.param_name && f.payload) {
                                                    headers = `Host: ${u.host}\n${f.param_name}: ${f.payload}\nAccept: */*`;
                                                  }
                                                  rawRequest = `${method} ${path} HTTP/1.1\n${headers}\n\n`;
                                                  tabName = `${method} ${path.slice(0, 30)}`;
                                                }
                                                const tab = await createTab({ name: tabName, raw_request: rawRequest });
                                                new BroadcastChannel("pwnproxy-repeater").postMessage({ type: "new-tab", focusId: tab.id });
                                                window.dispatchEvent(new CustomEvent("pwnproxy-toast", { detail: { title: "Sent to Repeater", message: `Tab #${tab.id} created`, severity: "success", navTo: "/repeater" } }));
                                              } catch {
                                                window.dispatchEvent(new CustomEvent("pwnproxy-toast", { detail: { title: "Repeater error", message: "Failed to send", severity: "error" } }));
                                              }
                                            }}
                                            class="rounded px-1.5 py-0.5 text-xs text-neutral-500 hover:text-primary-400 hover:bg-neutral-800"
                                            title="Send to Repeater"
                                          >
                                            Repeater
                                          </button>
                                        </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {totalPages > 1 && (
              <div class="mt-4 flex items-center justify-center gap-2">
                <button
                  disabled={safePage === 0}
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  class="rounded border border-neutral-700 px-3 py-1.5 text-xs text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-200 disabled:opacity-40"
                >
                  Previous
                </button>
                {Array.from({ length: totalPages }, (_, i) => (
                  <button
                    key={i}
                    onClick={() => setPage(i)}
                    class={`rounded px-3 py-1.5 text-xs transition-colors ${
                      i === safePage
                        ? "bg-primary-600 text-white"
                        : "border border-neutral-700 text-neutral-400 hover:bg-neutral-800 hover:text-neutral-200"
                    }`}
                  >
                    {i + 1}
                  </button>
                ))}
                <button
                  disabled={safePage >= totalPages - 1}
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  class="rounded border border-neutral-700 px-3 py-1.5 text-xs text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-200 disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function sevColor(severity: string): string {
  const map: Record<string, string> = {
    critical: "text-red-400",
    high: "text-orange-400",
    medium: "text-yellow-400",
    low: "text-blue-400",
    info: "text-neutral-400",
  };
  return map[severity] ?? "text-neutral-400";
}

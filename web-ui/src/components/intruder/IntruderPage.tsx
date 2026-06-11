import { useEffect, useRef, useState } from "preact/hooks";
import { runIntruder, replayPayload, listWordlists } from "@/api/intruder/calls";
import type { IntruderResult, ReplayResponse, WordlistEntry } from "@/api/intruder/types";
import { listTasks, pollTask, cancelTask, deleteTask } from "@/api/task/calls";
import type { TaskStatus, TaskSummary } from "@/api/task/types";

const POLL_INTERVAL = 1500;

type SortKey = "request_id" | "payload" | "status_code" | "response_length" | "timing_ms";

function statusColor(sc: number): string {
  if (sc >= 200 && sc < 300) return "text-success-500";
  if (sc >= 300 && sc < 400) return "text-blue-400";
  if (sc >= 400 && sc < 500) return "text-warning-400";
  if (sc >= 500) return "text-danger-500";
  return "text-neutral-500";
}

function fmtBytes(n: number): string {
  if (n >= 1024) return `${(n / 1024).toFixed(1)}k`;
  return String(n);
}

function extractHost(raw: string): string {
  const m = raw.match(/^Host:\s*(\S+)/im);
  return m ? m[1] : "?";
}

function escapeHtml(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

export function IntruderPage() {
  const [attacks, setAttacks] = useState<TaskStatus[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [results, setResults] = useState<IntruderResult[]>([]);
  const [rawRequest, setRawRequest] = useState("GET /§path§ HTTP/1.1\nHost: httpbin.org\n\n");
  const [mode, setMode] = useState("sniper");
  const [wordlistPath, setWordlistPath] = useState("");
  const [concurrency, setConcurrency] = useState(10);
  const [maxResults, setMaxResults] = useState(100);
  const [running, setRunning] = useState(false);
  const [preview, setPreview] = useState<ReplayResponse | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("request_id");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filterText, setFilterText] = useState("");
  const [draftId, setDraftId] = useState(0);
  const [showConfig, setShowConfig] = useState(true);
  const [renderMode, setRenderMode] = useState<"raw" | "render">("raw");
  const [showFullBody, setShowFullBody] = useState(false);
  const [wordlists, setWordlists] = useState<WordlistEntry[]>([]);
  const [showWordPicker, setShowWordPicker] = useState(false);
  const [loadingWordlists, setLoadingWordlists] = useState(false);
  const wordlistInputRef = useRef<HTMLInputElement>(null);
  const pollTimers = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());

  function upsertAttack(t: TaskStatus) {
    setAttacks((prev) => {
      const idx = prev.findIndex((a) => a.id === t.id);
      if (idx >= 0) {
        const copy = [...prev];
        copy[idx] = t;
        return copy;
      }
      return [t, ...prev];
    });
  }

  function removeFromAttacks(id: string) {
    setAttacks((prev) => prev.filter((a) => a.id !== id));
    if (selectedId === id) { setSelectedId(null); setShowConfig(true); setResults([]); setPreview(null); }
    if (!id.startsWith("draft-")) {
      const t = pollTimers.current.get(id);
      if (t) { clearInterval(t); pollTimers.current.delete(id); }
    }
  }

  function startBackgroundPoll(taskId: string) {
    if (pollTimers.current.has(taskId)) return;
    const timer = setInterval(async () => {
      try {
        const task = await pollTask(taskId);
        upsertAttack(task);
        if (selectedId === taskId) {
          const taskResults = (task.result?.results as IntruderResult[]) ?? [];
          setResults(taskResults);
        }
        if (task.status === "completed" || task.status === "failed" || task.status === "cancelled") {
          clearInterval(timer);
          pollTimers.current.delete(taskId);
          if (task.status === "completed") {
            window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
              detail: { title: "Attack complete", message: "", severity: "info" },
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
    listTasks("intruder")
      .then(({ tasks }) => {
        const all = tasks as TaskSummary[];
        Promise.all(all.map((t) => pollTask(t.id).catch(() => null)))
          .then((details) => {
            const valid = details.filter(Boolean) as TaskStatus[];
            setAttacks(valid);
            for (const t of valid) {
              if (t.status === "running") startBackgroundPoll(t.id);
            }
          });
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!showWordPicker) return;
    const handler = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest(".wordlist-picker-wrap")) setShowWordPicker(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showWordPicker]);

  function selectAttack(id: string) {
    const task = attacks.find((a) => a.id === id);
    if (task?.status === "draft") {
      setSelectedId(id);
      setShowConfig(true);
      setPreview(null);
      return;
    }
    setSelectedId(id);
    setShowConfig(false);
    setPreview(null);
    if (task) {
      setResults((task.result?.results as IntruderResult[]) ?? []);
      setRawRequest((task.config?.raw_request as string) ?? "");
      setMode((task.config?.mode as string) ?? "sniper");
      setWordlistPath((task.config?.wordlist_path as string) ?? "");
      setConcurrency((task.config?.concurrency as number) ?? 10);
    }
  }

  async function handleStart() {
    if (!rawRequest.trim()) {
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Validation error", message: "Raw request is required", severity: "error" },
      }));
      return;
    }
    if (!wordlistPath.trim()) {
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Validation error", message: "Wordlist path is required", severity: "error" },
      }));
      return;
    }
    setRunning(true);
    try {
      const data = await runIntruder({
        raw_request: rawRequest,
        mode: mode as "sniper" | "cluster_bomb",
        wordlist_path: wordlistPath,
        concurrency,
      });
      setAttacks((prev) => prev.filter((a) => a.id !== selectedId));
      const placeholder = {
        id: data.task_id, type: "intruder", status: "running",
        progress: 0, total: data.total,
        config: { raw_request: rawRequest, mode, wordlist_path: wordlistPath, concurrency },
        result: null, error: null,
        created_at: new Date().toISOString(), completed_at: null,
      } as TaskStatus;
      upsertAttack(placeholder);
      selectAttack(data.task_id);
      startBackgroundPoll(data.task_id);
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Attack started", message: `${data.total} payloads`, severity: "info" },
      }));
    } catch (err: any) {
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Error", message: err.message ?? "Unknown error", severity: "error" },
      }));
    } finally {
      setRunning(false);
    }
  }

  async function handleStop(id: string) {
    try {
      await cancelTask(id);
    } catch {}
    setAttacks((prev) => prev.map((a) =>
      a.id === id ? { ...a, status: "cancelled", completed_at: new Date().toISOString() } : a
    ));
    const t = pollTimers.current.get(id);
    if (t) { clearInterval(t); pollTimers.current.delete(id); }
    window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
      detail: { title: "Attack stopped", message: "", severity: "info" },
    }));
  }

  async function handleDelete(id: string) {
    if (!id.startsWith("draft-")) {
      try {
        await deleteTask(id);
      } catch {}
    }
    removeFromAttacks(id);
    window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
      detail: { title: "Attack deleted", message: "", severity: "info" },
    }));
  }

  async function handleReplay(payload: string) {
    setPreviewLoading(true);
    setPreview(null);
    try {
      const resp = await replayPayload(rawRequest, payload);
      setPreview(resp);
      setShowFullBody(false);
      setRenderMode("raw");
    } catch {
      setPreview({ status_code: 0, headers: {}, body: "", timing_ms: 0, error: "Replay failed" });
    } finally {
      setPreviewLoading(false);
    }
  }

  function toggleSort(col: SortKey) {
    if (sortKey === col) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(col);
      setSortDir("asc");
    }
  }

  function sortArrow(col: SortKey): string {
    return sortKey === col ? (sortDir === "asc" ? " ↑" : " ↓") : "";
  }

  const filtered = results
    .filter((r) => !filterText || r.payload.toLowerCase().includes(filterText.toLowerCase()))
    .sort((a, b) => {
      const mul = sortDir === "asc" ? 1 : -1;
      if (sortKey === "payload") return mul * a.payload.localeCompare(b.payload);
      return mul * (Number(a[sortKey]) - Number(b[sortKey]));
    });

  const selectedAttack = attacks.find((a) => a.id === selectedId);

  const previewBody = preview?.body ?? "";
  const truncatedBody = showFullBody ? previewBody : previewBody.slice(0, 5000);
  const isHtml = preview && (preview.headers["content-type"] ?? "").includes("text/html");

  return (
    <div class="flex h-full flex-col">
      {/* Header */}
      <div class="mb-4 flex items-center justify-between">
        <h1 class="text-xl font-bold text-neutral-50">Intruder</h1>
        <button
          onClick={() => {
            setDraftId((n) => n + 1);
            setRawRequest("GET /§path§ HTTP/1.1\nHost: example.com\n\n");
            setMode("sniper");
            setWordlistPath("");
            setConcurrency(10);
            setMaxResults(100);
            setResults([]);
            setPreview(null);
            setSelectedId(null);
            setShowConfig(true);
            const draft: TaskStatus = {
              id: `draft-${draftId + 1}`, type: "intruder", status: "draft",
              progress: 0, total: 0, config: { mode: "sniper", wordlist_path: "", concurrency: 10 },
              result: null, error: null,
              created_at: new Date().toISOString(), completed_at: null,
            };
            setAttacks((prev) => [draft, ...prev]);
          }}
          class="inline-flex items-center gap-1.5 rounded-md bg-primary-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-primary-500"
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="h-3.5 w-3.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          New Attack
        </button>
      </div>

      {/* Sidebar + Main */}
      <div class="flex flex-1 gap-3 lg:gap-2 overflow-hidden">
        {/* Sidebar */}
        <div class="flex w-[260px] shrink-0 flex-col rounded-lg border border-neutral-800 bg-neutral-950 lg:w-[220px]">
          <div class="border-b border-neutral-800 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-neutral-400">
            Attacks ({attacks.length})
          </div>
          <div class="flex-1 overflow-y-auto p-2 space-y-1.5">
            {attacks.length === 0 && (
              <div class="flex flex-col items-center justify-center py-8 text-xs text-neutral-600">
                <p>No attacks yet</p>
              </div>
            )}
            {attacks.map((a) => {
              const draft_ = a.status === "draft";
              const sel = a.id === selectedId;
              const running_ = a.status === "running";
              const host = draft_ ? "New Attack" : extractHost((a.config?.raw_request as string) ?? (a.config as any)?.rawRequest ?? "");
              const words = a.total ?? 0;
              return (
                  <div
                    key={a.id}
                    onClick={() => selectAttack(a.id)}
                    class={`cursor-pointer rounded-md px-2 lg:px-1.5 py-1.5 text-xs transition-colors ${
                      sel ? "bg-primary-900/40 ring-1 ring-primary-700" : "hover:bg-neutral-800/60"
                    }`}
                  >
                  <div class="flex items-center gap-2">
                    {draft_ ? (
                      <span class="inline-block h-2 w-2 rounded-full bg-yellow-500" />
                    ) : running_ ? (
                      <span class="inline-block h-2 w-2 animate-pulse rounded-full bg-blue-400" />
                    ) : a.status === "completed" ? (
                      <span class="inline-block h-2 w-2 rounded-full bg-success-500" />
                    ) : a.status === "failed" ? (
                      <span class="inline-block h-2 w-2 rounded-full bg-danger-500" />
                    ) : (
                      <span class="inline-block h-2 w-2 rounded-full bg-neutral-600" />
                    )}
                    <span class="flex-1 truncate font-medium text-neutral-200">{host}</span>
                  </div>
                  <div class="mt-1 flex items-center gap-2 text-[10px] text-neutral-500">
                    {draft_ ? (
                      <span class="italic text-yellow-500">Not started</span>
                    ) : (
                      <><span class="uppercase">{a.config?.mode as string ?? mode}</span><span>·</span><span>{words} words</span></>
                    )}
                  </div>
                  {running_ && (
                    <div class="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-neutral-800">
                      <div
                        class="h-full rounded-full bg-blue-500 transition-all"
                        style={{ width: `${a.total > 0 ? Math.round((a.progress ?? 0) / a.total * 100) : 0}%` }}
                      />
                    </div>
                  )}
                  {!draft_ && (
                    <div class="mt-1 flex gap-1">
                      {running_ && (
                        <button
                          onClick={(e) => { e.stopPropagation(); handleStop(a.id); }}
                          class="rounded bg-red-900/40 px-1.5 py-0.5 text-[10px] font-semibold text-red-400 hover:bg-red-800/60"
                        >Stop</button>
                      )}
                      <button
                        onClick={(e) => { e.stopPropagation(); handleDelete(a.id); }}
                        class="rounded bg-neutral-800 px-1.5 py-0.5 text-[10px] text-neutral-500 hover:bg-neutral-700 hover:text-red-400"
                      >Delete</button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Main panel */}
        <div class="flex flex-1 flex-col overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950">
          {showConfig || !selectedAttack ? (
            /* Config form */
            <div class="flex flex-1 flex-col gap-3 overflow-y-auto overflow-x-hidden p-4">
              <h3 class="text-sm font-semibold text-neutral-200">Configuration</h3>
              <div>
                <label class="mb-1 block text-xs text-neutral-400">Raw request (use § markers)</label>
                <textarea
                  value={rawRequest}
                  onInput={(e) => setRawRequest((e.target as HTMLTextAreaElement).value)}
                  rows={8}
                  class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 font-mono text-xs text-neutral-100 placeholder-neutral-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
              </div>
              <div class="grid grid-cols-2 gap-3 lg:grid-cols-1">
                <div>
                  <label class="mb-1 block text-xs text-neutral-400">Mode</label>
                  <select value={mode} onChange={(e) => setMode((e.target as HTMLSelectElement).value)}
                    class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100"
                  >
                    <option value="sniper">Sniper</option>
                    <option value="cluster_bomb">Cluster Bomb</option>
                  </select>
                </div>
                <div>
                  <label class="mb-1 block text-xs text-neutral-400">Wordlist</label>
                  <div class="flex gap-2 min-w-0">
                    <input value={wordlistPath} onInput={(e) => setWordlistPath((e.target as HTMLInputElement).value)}
                      placeholder="/path/to/wordlist.txt"
                      class="min-w-0 flex-1 rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 placeholder-neutral-500"
                    />
                    <div class="relative shrink-0 wordlist-picker-wrap">
                      <input type="file" accept=".txt,.lst" class="hidden" ref={wordlistInputRef}
                        onChange={(e) => {
                          const files = (e.target as HTMLInputElement).files;
                          if (!files?.[0]) return;
                          const p = (files[0] as any).path;
                          if (p) { setWordlistPath(p); return; }
                          setWordlistPath(files[0].name);
                          window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
                            detail: { title: "Tip", message: "Type the full path manually — browser didn't expose the file path", severity: "info" },
                          }));
                        }}
                      />
                      <button onClick={async () => {
                        if (showWordPicker) { setShowWordPicker(false); return; }
                        setLoadingWordlists(true);
                        setShowWordPicker(true);
                        try {
                          const wl = await listWordlists();
                          setWordlists(wl);
                        } catch { setWordlists([]); }
                        setLoadingWordlists(false);
                      }}
                        class="rounded-md border border-primary-700 bg-primary-900/30 px-3 text-xs font-medium text-primary-400 transition-colors hover:bg-primary-800/50"
                      >Browse</button>
                      {showWordPicker && (
                        <div class="absolute right-0 top-full z-50 mt-1 w-72 max-h-64 overflow-y-auto rounded-md border border-neutral-700 bg-neutral-900 shadow-lg">
                          {loadingWordlists ? (
                            <div class="flex items-center justify-center gap-2 px-3 py-4 text-xs text-neutral-500">
                              <svg class="h-3.5 w-3.5 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                              Loading...
                            </div>
                          ) : wordlists.length === 0 ? (
                            <div class="border-b border-neutral-800 px-3 py-3 text-xs text-neutral-500">No wordlists in ~/.pwnproxy/wordlists/</div>
                          ) : wordlists.map((wl) => (
                            <div key={wl.path}
                              onClick={() => { setWordlistPath(wl.path); setShowWordPicker(false); }}
                              class="cursor-pointer border-b border-neutral-800 px-3 py-2 text-xs text-neutral-300 transition-colors last:border-0 hover:bg-neutral-800"
                            >
                              <div class="font-medium">{wl.name}</div>
                              <div class="mt-0.5 text-[10px] text-neutral-500">{wl.line_count} lines · {fmtBytes(wl.size_bytes)}</div>
                            </div>
                          ))}
                          <div
                            onClick={() => { wordlistInputRef.current?.click(); setShowWordPicker(false); }}
                            class="flex cursor-pointer items-center gap-2 border-t border-neutral-800 px-3 py-2 text-xs font-medium text-primary-400 transition-colors hover:bg-neutral-800"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="h-3.5 w-3.5"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/><line x1="12" y1="6" x2="12" y2="14"/><line x1="9" y1="10" x2="15" y2="10"/></svg>
                            Open local file
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
              <div class="grid grid-cols-2 gap-3 lg:grid-cols-1">
                <div>
                  <label class="mb-1 block text-xs text-neutral-400">Concurrency</label>
                  <input type="number" value={concurrency} min={1}
                    onInput={(e) => setConcurrency(parseInt((e.target as HTMLInputElement).value) || 10)}
                    class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100"
                  />
                </div>
                <div>
                  <label class="mb-1 block text-xs text-neutral-400">Max results</label>
                  <input type="number" value={maxResults} min={1}
                    onInput={(e) => setMaxResults(parseInt((e.target as HTMLInputElement).value) || 100)}
                    class="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100"
                  />
                </div>
              </div>
              <div class="flex gap-2">
                <button onClick={handleStart} disabled={running}
                  class="inline-flex items-center gap-1.5 rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="h-4 w-4"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                  {running ? "Starting..." : "Start Attack"}
                </button>
                {selectedId && attacks.find((a) => a.id === selectedId)?.status === "running" && (
                  <button onClick={() => handleStop(selectedId)}
                    class="inline-flex items-center gap-1.5 rounded-md bg-red-900/60 px-4 py-2 text-sm font-medium text-red-300 transition-colors hover:bg-red-800/80"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-4 w-4"><rect x="6" y="6" width="12" height="12" rx="1"/></svg>
                    Stop
                  </button>
                )}
              </div>
            </div>
          ) : (
            /* Results + Preview */
            <>
              {/* Results table */}
              <div class="flex flex-1 flex-col overflow-hidden">
                {results.length === 0 && (
                  <div class="flex flex-1 items-center justify-center text-sm text-neutral-600">
                    {selectedAttack?.status === "running" ? "Waiting for results..." : "No results"}
                  </div>
                )}
                {results.length > 0 && (
                  <>
                    <div class="flex items-center gap-3 border-b border-neutral-800 px-4 py-2">
                      <input value={filterText} onInput={(e) => setFilterText((e.target as HTMLInputElement).value)}
                        placeholder="Filter by payload..."
                        class="flex-1 rounded border border-neutral-700 bg-neutral-800 px-2 py-1 text-xs text-neutral-100 placeholder-neutral-500"
                      />
                      <span class="text-xs text-neutral-500">{filtered.length} / {results.length}</span>
                    </div>
                    <div class="flex-1 overflow-y-auto">
                      <table class="w-full text-xs">
                        <thead>
                          <tr class="sticky top-0 border-b border-neutral-800 bg-neutral-900">
                            {(["request_id", "payload", "status_code", "response_length", "timing_ms"] as SortKey[]).map((col) => (
                              <th key={col}
                                onClick={() => toggleSort(col)}
                                class="cursor-pointer px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400 hover:text-neutral-200 lg:px-2"
                              >
                                {col === "request_id" ? "#" : col === "status_code" ? "Status" : col === "response_length" ? "Length" : col === "timing_ms" ? "Time" : "Payload"}{sortArrow(col)}
                              </th>
                            ))}
                            <th class="px-3 py-2 text-left font-semibold uppercase tracking-wider text-neutral-400 lg:px-2">Resp</th>
                          </tr>
                        </thead>
                        <tbody class="divide-y divide-neutral-800">
                          {filtered.map((r) => (
                            <tr key={r.request_id} class="bg-neutral-950 hover:bg-neutral-900/50">
                              <td class="px-3 py-1 lg:px-2 lg:py-1 text-neutral-500">{r.request_id}</td>
                              <td class="max-w-[160px] truncate px-3 py-1 font-mono text-neutral-300 lg:max-w-[80px] lg:px-2 xl:max-w-[160px]" title={r.payload}>{escapeHtml(r.payload)}</td>
                              <td class={`px-3 py-1 font-semibold lg:px-2 ${statusColor(r.status_code)}`}>{r.status_code}</td>
                              <td class="px-3 py-1 text-neutral-400 lg:px-2">{fmtBytes(r.response_length)}</td>
                              <td class="px-3 py-1 text-neutral-500 lg:px-2">{r.timing_ms?.toFixed(0)}ms</td>
                              <td class="px-3 py-1 lg:px-2">
                                <button onClick={() => handleReplay(r.payload)}
                                  class="rounded p-1 text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-primary-400"
                                  title="Preview response"
                                >
                                  {previewLoading ? (
                                    <svg class="h-3.5 w-3.5 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                                  ) : (
                                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="h-3.5 w-3.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                                  )}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </div>

              {/* Response preview */}
              <div class="shrink-0 border-t border-neutral-800" style={{ height: "240px" }}>
                <div class="flex h-full flex-col">
                  {!preview && !previewLoading && (
                    <div class="flex h-full items-center justify-center text-xs text-neutral-500">
                      Click <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="mx-1 h-3.5 w-3.5"><polygon points="5 3 19 12 5 21 5 3"/></svg> on a result row to preview the response
                    </div>
                  )}
                  {previewLoading && (
                    <div class="flex h-full items-center justify-center gap-2 text-xs text-neutral-500">
                      <svg class="h-4 w-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                      Loading...
                    </div>
                  )}
                  {preview && !previewLoading && (
                    <>
                      <div class={`flex items-center justify-between border-b border-neutral-800 px-3 py-1.5 ${
                        preview.status_code >= 200 && preview.status_code < 300 ? "bg-success-900/20" :
                        preview.status_code >= 400 ? "bg-danger-900/20" : "bg-neutral-900"
                      }`}>
                        <span class="text-xs font-semibold text-neutral-200">
                          HTTP/1.1 {preview.status_code} {preview.timing_ms.toFixed(0)}ms
                        </span>
                        <div class="flex gap-1">
                          <button onClick={() => setRenderMode("raw")}
                            class={`rounded px-1.5 py-0.5 text-[10px] ${renderMode === "raw" ? "bg-primary-700 text-white" : "text-neutral-500 hover:text-neutral-200"}`}
                          >Raw</button>
                          {isHtml && (
                            <button onClick={() => setRenderMode("render")}
                              class={`rounded px-1.5 py-0.5 text-[10px] ${renderMode === "render" ? "bg-primary-700 text-white" : "text-neutral-500 hover:text-neutral-200"}`}
                            >Render</button>
                          )}
                        </div>
                      </div>
                      <div class="flex-1 overflow-y-auto p-3">
                        {preview.error && (
                          <p class="text-xs text-danger-500">Error: {preview.error}</p>
                        )}
                        {renderMode === "raw" && (
                          <pre class="whitespace-pre-wrap text-xs text-neutral-300">
                            {Object.entries(preview.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
                            {"\n\n"}
                            {truncatedBody}
                            {!showFullBody && previewBody.length > 5000 && (
                              <button onClick={() => setShowFullBody(true)}
                                class="mt-1 text-primary-400 hover:text-primary-300"
                              >Show full response ({previewBody.length - 5000} more chars)</button>
                            )}
                          </pre>
                        )}
                        {renderMode === "render" && isHtml && (
                          <iframe sandbox="allow-same-origin" srcdoc={previewBody}
                            class="h-full w-full rounded border-0 bg-white"
                            title="Response preview"
                          />
                        )}
                      </div>
                    </>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
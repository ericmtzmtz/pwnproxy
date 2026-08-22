import { useState, useEffect, useCallback, useRef } from "preact/hooks";
import { sendRequest, listTabs, createTab, updateTab, deleteTab } from "@/api/repeater/calls";
import type { RepeaterTab } from "@/api/repeater/types";
import { pollTask, listTasks } from "@/api/task/calls";
import { RequestEditor } from "./RequestEditor";
import { ResponseViewer } from "./ResponseViewer";
import type { HttpResponse } from "./ResponseViewer";
import { RepeaterHistory } from "./RepeaterHistory";

interface TabWithResp {
  meta: RepeaterTab;
  response: HttpResponse | null;
  loading?: boolean;
  modified?: boolean;
}

const CHANNEL = new BroadcastChannel("pwnproxy-repeater");

type LayoutMode = "split" | "request" | "response";

function methodFromRaw(raw: string): string {
  const m = raw.trim().match(/^(\w+)/);
  return m ? m[1].toUpperCase() : "GET";
}

function hostFromRaw(raw: string): string {
  const m = raw.match(/^Host:\s*(\S+)/im);
  return m ? m[1] : "";
}

function endpointFromRaw(raw: string): string {
  const m = raw.trim().match(/^\w+\s+(\S+)/);
  if (!m) return "new";
  try {
    const u = new URL(m[1]);
    return u.pathname.split("/").filter(Boolean).pop() || u.pathname;
  } catch {
    return m[1].split("?")[0].split("/").filter(Boolean).pop() || m[1];
  }
}

function statusColor(code: number | null): string {
  if (code === null || code === 0) return "text-neutral-600";
  if (code >= 500) return "text-red-400";
  if (code >= 400) return "text-orange-400";
  if (code >= 300) return "text-blue-400";
  if (code >= 200) return "text-green-400";
  return "text-neutral-400";
}

function methodColor(m: string): string {
  switch (m) {
    case "GET": return "text-sky-400";
    case "POST": return "text-green-400";
    case "PUT": case "PATCH": return "text-yellow-400";
    case "DELETE": return "text-red-400";
    default: return "text-neutral-400";
  }
}

export function RepeaterPage() {
  const [tabs, setTabs] = useState<TabWithResp[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [sending, setSending] = useState<Record<number, boolean>>({});
  const [layout, setLayout] = useState<LayoutMode>("split");
  const [showHistory, setShowHistory] = useState(false);
  const [loading, setLoading] = useState(true);
  const loadedRef = useRef(false);

  const activeTab = tabs.find((t) => t.meta.id === activeId) ?? null;

  useEffect(() => {
    if (loadedRef.current) return;
    loadedRef.current = true;
    (async () => {
      try {
        const tabsData = await listTabs();
        if (tabsData.length > 0) {
          const mapped: TabWithResp[] = [];
          for (const t of tabsData) {
            let resp: HttpResponse | null = null;
            if (t.last_task_id) {
              try {
                const task = await pollTask(t.last_task_id);
                const r = task.result;
                if (r && r.status_code !== undefined) {
                  resp = {
                    status_code: r.status_code,
                    headers: r.headers ?? {},
                    body: r.body ?? "",
                    timing_ms: r.duration_ms ?? 0,
                  };
                }
              } catch { /* task gone */ }
            }
            mapped.push({ meta: t, response: resp });
          }
          setTabs(mapped);
          setActiveId(tabsData[0].id);
        }
      } catch { /* API down */ } finally {
        setLoading(false);
      }
    })();
  }, []);

  // BroadcastChannel listener for new tabs
  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (e.data?.type === "new-tab") {
        listTabs().then((tabsData) => {
          setTabs((prev) =>
            tabsData.map((t) => {
              const existing = prev.find((x) => x.meta.id === t.id);
              return { meta: t, response: existing?.response ?? null };
            }),
          );
          if (e.data?.focusId) setActiveId(e.data.focusId);
        });
      }
    };
    CHANNEL.addEventListener("message", handler);
    return () => CHANNEL.removeEventListener("message", handler);
  }, []);

  async function addTab() {
    try {
      const created = await createTab({ raw_request: "" });
      setTabs((prev) => [...prev, { meta: created, response: null }]);
      setActiveId(created.id);
    } catch { /* ignore */ }
  }

  async function closeTab(id: number, e: MouseEvent) {
    e.stopPropagation();
    if (tabs.length <= 1) return;
    try { await deleteTab(id); } catch { /* ignore */ }
    setTabs((prev) => {
      const idx = prev.findIndex((t) => t.meta.id === id);
      const next = prev.filter((t) => t.meta.id !== id);
      if (activeId === id) {
        const newIdx = Math.min(idx, next.length - 1);
        setActiveId(next[newIdx]?.meta.id ?? null);
      }
      return next;
    });
  }

  const saveTimers = useRef<Record<number, ReturnType<typeof setTimeout>>>({});

  function updateRequest(id: number, val: string) {
    setTabs((prev) =>
      prev.map((t) => (t.meta.id === id ? { ...t, meta: { ...t.meta, raw_request: val }, modified: true } : t)),
    );
    if (saveTimers.current[id]) clearTimeout(saveTimers.current[id]);
    saveTimers.current[id] = setTimeout(async () => {
      try { await updateTab(id, { raw_request: val }); } catch { /* silent */ }
    }, 800);
  }

  async function renameTab(id: number, name: string) {
    try {
      const updated = await updateTab(id, { name });
      setTabs((prev) => prev.map((t) => (t.meta.id === id ? { ...t, meta: updated } : t)));
    } catch { /* ignore */ }
  }

  async function handleSend(id: number) {
    const tab = tabs.find((t) => t.meta.id === id);
    if (!tab || !tab.meta.raw_request.trim()) return;
    setSending((prev) => ({ ...prev, [id]: true }));
    setTabs((prev) => prev.map((t) => (t.meta.id === id ? { ...t, loading: true } : t)));
    try {
      const data = await sendRequest({ raw_request: tab.meta.raw_request, tab_id: id });
      await updateTab(id, { last_task_id: data.task_id });
      // poll for full body
      let full: HttpResponse = {
        status_code: data.status_code,
        headers: data.headers,
        body: data.body_preview,
        timing_ms: data.timing_ms,
      };
      try {
        const task = await pollTask(data.task_id);
        const r = task.result;
        if (r && r.body !== undefined) {
          full = { status_code: r.status_code, headers: r.headers ?? {}, body: r.body ?? "", timing_ms: r.duration_ms ?? 0 };
        }
      } catch { /* use preview */ }
      setTabs((prev) =>
        prev.map((t) =>
          t.meta.id === id
            ? { ...t, meta: { ...t.meta, last_task_id: data.task_id }, response: full, loading: false, modified: false }
            : t,
        ),
      );
    } catch (err: any) {
      setTabs((prev) =>
        prev.map((t) =>
          t.meta.id === id
            ? { ...t, response: { status_code: 0, headers: {}, body: `Error: ${err.message}`, timing_ms: 0 }, loading: false }
            : t,
        ),
      );
    } finally {
      setSending((prev) => ({ ...prev, [id]: false }));
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "n") {
      e.preventDefault();
      addTab();
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && activeTab) {
      e.preventDefault();
      handleSend(activeTab.meta.id);
    }
  }

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [activeTab, tabs]);

  if (loading) {
    return (
      <div class="flex items-center justify-center py-20 text-sm text-neutral-500">
        <svg class="mr-2 h-5 w-5 animate-spin text-primary-400" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
        Loading tabs…
      </div>
    );
  }

  const activeHost = activeTab ? hostFromRaw(activeTab.meta.raw_request) : "";
  const activeMethod = activeTab ? methodFromRaw(activeTab.meta.raw_request) : "";
  const activeStatus = activeTab?.response?.status_code ?? null;

  return (
    <div class="flex h-full flex-col">
      {/* Compact header */}
      <div class="flex items-center gap-3 border-b border-neutral-800 px-3 py-1.5">
        <span class="text-sm font-semibold text-neutral-200">⚡ Repeater</span>
        {activeHost && (
          <span class="flex items-center gap-1.5 text-xs text-neutral-500">
            <span class="h-1.5 w-1.5 rounded-full bg-green-500" />
            Target: <span class="font-mono text-neutral-300">{activeHost}</span>
          </span>
        )}
        <div class="ml-auto flex items-center gap-1">
          <button
            onClick={addTab}
            class="inline-flex items-center gap-1 rounded-md border border-neutral-800 px-2 py-1 text-[11px] text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-200"
          >
            <span class="text-xs">+</span> New Tab
          </button>
          <button
            onClick={() => setShowHistory((p) => !p)}
            class={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] transition-colors ${
              showHistory ? "border-primary-700 bg-primary-900/30 text-primary-300" : "border-neutral-800 text-neutral-400 hover:bg-neutral-800 hover:text-neutral-200"
            }`}
          >
            History
          </button>
        </div>
      </div>

      {/* Tab bar */}
      <div class="flex items-center gap-0.5 overflow-x-auto border-b border-neutral-800 bg-neutral-950">
        {tabs.map((tab) => {
          const isActive = tab.meta.id === activeId;
          const method = methodFromRaw(tab.meta.raw_request);
          const endpoint = endpointFromRaw(tab.meta.raw_request);
          const status = tab.response?.status_code ?? null;
          return (
            <button
              key={tab.meta.id}
              onClick={() => setActiveId(tab.meta.id)}
              class={`group flex shrink-0 items-center gap-1.5 border-r border-neutral-800 px-3 py-1.5 text-[11px] transition-colors ${
                isActive ? "bg-neutral-800 text-neutral-200" : "text-neutral-500 hover:bg-neutral-800/50 hover:text-neutral-300"
              }`}
            >
              {tab.loading ? (
                <svg class="h-3 w-3 animate-spin text-primary-400" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
              ) : (
                <span class={`h-1.5 w-1.5 rounded-full ${tab.modified ? "bg-yellow-400" : status ? statusColor(status) : "bg-neutral-700"}`} />
              )}
              <span class={`font-semibold ${methodColor(method)}`}>{method}</span>
              <span class="max-w-[100px] truncate font-mono">{endpoint}</span>
              {status && status > 0 && <span class={statusColor(status)}>{status}</span>}
              {tab.response && <span class="text-neutral-600">{tab.response.timing_ms}ms</span>}
              {tabs.length > 1 && (
                <span
                  onClick={(e) => closeTab(tab.meta.id, e)}
                  class="hidden h-3.5 w-3.5 items-center justify-center rounded text-[10px] text-neutral-600 group-hover:flex hover:bg-neutral-700 hover:text-neutral-300"
                >
                  ✕
                </span>
              )}
            </button>
          );
        })}
        <button
          onClick={addTab}
          class="flex shrink-0 items-center px-2.5 py-1.5 text-xs text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
        >
          +
        </button>
      </div>

      {/* Layout controls */}
      {activeTab && (
        <div class="flex items-center gap-0.5 border-b border-neutral-800 px-2 py-1">
          {(["split", "request", "response"] as LayoutMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setLayout(m)}
              class={`rounded px-2 py-0.5 text-[10px] font-medium capitalize transition-colors ${
                layout === m ? "bg-neutral-800 text-neutral-200" : "text-neutral-500 hover:text-neutral-300"
              }`}
            >
              {m === "split" ? "Split" : m === "request" ? "Max Request" : "Max Response"}
            </button>
          ))}
        </div>
      )}

      {/* Main layout */}
      {activeTab && (
        <div class="flex min-h-0 flex-1">
          <div class={`grid min-h-0 flex-1 gap-0 ${layout === "split" ? "grid-cols-2" : "grid-cols-1"}`}>
            {layout !== "response" && (
              <div class="flex min-h-0 flex-col border-r border-neutral-800">
                <div class="border-b border-neutral-800 bg-neutral-950 px-3 py-1">
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">Request</span>
                </div>
                <div class="min-h-0 flex-1">
                  <RequestEditor
                    value={activeTab.meta.raw_request}
                    onChange={(val) => updateRequest(activeTab.meta.id, val)}
                    onSend={() => handleSend(activeTab.meta.id)}
                    sending={sending[activeTab.meta.id]}
                  />
                </div>
              </div>
            )}
            {layout !== "request" && (
              <div class="flex min-h-0 flex-col">
                <div class="border-b border-neutral-800 bg-neutral-950 px-3 py-1">
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">Response</span>
                </div>
                <div class="min-h-0 flex-1">
                  <ResponseViewer response={activeTab.response} loading={activeTab.loading} />
                </div>
              </div>
            )}
          </div>
          {showHistory && (
            <RepeaterHistory
              onRestore={(raw, name) => {
                // Create a new tab with the historical request
                createTab({ name, raw_request: raw }).then((created) => {
                  setTabs((prev) => [...prev, { meta: created, response: null }]);
                  setActiveId(created.id);
                });
              }}
              onClose={() => setShowHistory(false)}
            />
          )}
        </div>
      )}
    </div>
  );
}

import { useState, useEffect, useCallback, useRef } from "preact/hooks";
import { sendRequest, listTabs, createTab, updateTab, deleteTab } from "@/api/repeater/calls";
import type { RepeaterTab } from "@/api/repeater/types";
import { pollTask } from "@/api/task/calls";

interface ResponseData {
  status_code: number;
  headers: Record<string, string>;
  body_preview: string;
  timing_ms: number;
}

interface TabWithResp {
  meta: RepeaterTab;
  response: ResponseData | null;
}

const CHANNEL = new BroadcastChannel("pwnproxy-repeater");

function parseUrlParams(): string | null {
  const params = new URLSearchParams(window.location.search);
  const url = params.get("url");
  const method = params.get("method");
  if (url && method) {
    // Build a raw request from url+method
    const u = new URL(url);
    const path = u.pathname + u.search;
    const host = u.host;
    const body = u.searchParams.get("body") || "";
    if (method.toUpperCase() === "GET" || !body) {
      return `${method.toUpperCase()} ${path} HTTP/1.1\nHost: ${host}\nUser-Agent: pwnproxy-repeater/0.1\nAccept: */*\n\n`;
    }
    return `${method.toUpperCase()} ${path} HTTP/1.1\nHost: ${host}\nUser-Agent: pwnproxy-repeater/0.1\nAccept: */*\nContent-Type: application/x-www-form-urlencoded\nContent-Length: ${body.length}\n\n${body}`;
  }
  return null;
}

export function RepeaterPage() {
  const [tabs, setTabs] = useState<TabWithResp[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [sending, setSending] = useState<Record<number, boolean>>({});
  const [renderHtml, setRenderHtml] = useState(false);
  const [loading, setLoading] = useState(true);
  const loadedRef = useRef(false);

  const activeTab = tabs.find((t) => t.meta.id === activeId) ?? null;

  // Load tabs on mount
  useEffect(() => {
    if (loadedRef.current) return;
    loadedRef.current = true;
    (async () => {
      try {
        const tabsData = await listTabs();
        if (tabsData.length > 0) {
          const mapped = await Promise.all(tabsData.map(async (t) => {
            let resp: ResponseData | null = null;
            if (t.last_task_id) {
              try {
                const task = await pollTask(t.last_task_id);
                const r = task.result;
                if (r && r.status_code !== undefined) {
                  const body = r.body ?? "";
                  resp = {
                    status_code: r.status_code,
                    headers: r.headers ?? {},
                    body_preview: body.slice(0, 500) + (body.length > 500 ? "..." : ""),
                    timing_ms: r.duration_ms ?? 0,
                  };
                }
              } catch { /* task gone, ignore */ }
            }
            return { meta: t, response: resp };
          }));
          setTabs(mapped);
          setActiveId(tabsData[0].id);
        }
      } catch {
        // fallback if API fails
      } finally {
        setLoading(false);
      }

      // Check URL params (legacy send-to-repeater from window.open)
      const raw = parseUrlParams();
      if (raw) {
        try {
          const created = await createTab({ raw_request: raw });
          setTabs((prev) => [...prev, { meta: created, response: null }]);
          setActiveId(created.id);
          // Clean URL
          window.history.replaceState({}, "", "/repeater");
        } catch {
          // ignore
        }
      }
    })();
  }, []);

  // Listen for BroadcastChannel "new-tab" messages
  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (e.data?.type === "new-tab") {
        // Refresh the list
        listTabs().then((tabsData) => {
          setTabs(tabsData.map((t) => {
            const existing = tabs.find((x) => x.meta.id === t.id);
            return { meta: t, response: existing?.response ?? null };
          }));
          // If no active tab set, or the new tab should be focused
          if (e.data?.focusId) {
            setActiveId(e.data.focusId);
          }
        });
      }
    };
    CHANNEL.addEventListener("message", handler);
    return () => CHANNEL.removeEventListener("message", handler);
  }, [tabs]);

  async function addTab() {
    try {
      const created = await createTab({ raw_request: "" });
      setTabs((prev) => [...prev, { meta: created, response: null }]);
      setActiveId(created.id);
    } catch {
      // ignore
    }
  }

  async function closeTab(id: number, e: MouseEvent) {
    e.stopPropagation();
    if (tabs.length <= 1) return;
    try {
      await deleteTab(id);
    } catch {
      // ignore — still remove locally
    }
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

  function updateRequest(id: number, val: string) {
    setTabs((prev) =>
      prev.map((t) => (t.meta.id === id ? { ...t, meta: { ...t.meta, raw_request: val } } : t)),
    );
    // Debounced save
    debouncedSave(id, val);
  }

  const saveTimers = useRef<Record<number, ReturnType<typeof setTimeout>>>({});

  function debouncedSave(id: number, raw: string) {
    if (saveTimers.current[id]) clearTimeout(saveTimers.current[id]);
    saveTimers.current[id] = setTimeout(async () => {
      try {
        await updateTab(id, { raw_request: raw });
      } catch {
        // silently fail
      }
    }, 800);
  }

  async function renameTab(id: number, name: string) {
    try {
      const updated = await updateTab(id, { name });
      setTabs((prev) =>
        prev.map((t) => (t.meta.id === id ? { ...t, meta: updated } : t)),
      );
    } catch {
      // ignore
    }
  }

  async function handleSend(id: number) {
    const tab = tabs.find((t) => t.meta.id === id);
    if (!tab || !tab.meta.raw_request.trim()) return;

    setSending((prev) => ({ ...prev, [id]: true }));
    try {
      const data = await sendRequest({ raw_request: tab.meta.raw_request, tab_id: id });
      await updateTab(id, { last_task_id: data.task_id });
      setTabs((prev) =>
        prev.map((t) =>
          t.meta.id === id
            ? { ...t, meta: { ...t.meta, last_task_id: data.task_id }, response: { status_code: data.status_code, headers: data.headers, body_preview: data.body_preview, timing_ms: data.timing_ms } }
            : t,
        ),
      );
    } catch (err: any) {
      setTabs((prev) =>
        prev.map((t) =>
          t.meta.id === id
            ? { ...t, response: { status_code: 0, headers: {}, body_preview: `Error: ${err.message}`, timing_ms: 0 } }
            : t,
        ),
      );
    } finally {
      setSending((prev) => ({ ...prev, [id]: false }));
    }
  }

  if (loading) {
    return (
      <div class="flex items-center justify-center py-20 text-sm text-neutral-500">
        <svg class="mr-2 h-5 w-5 animate-spin text-primary-400" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
        Loading tabs…
      </div>
    );
  }

  const resp = activeTab?.response;
  const statusClass = resp
    ? resp.status_code >= 400
      ? "text-red-400"
      : resp.status_code >= 200 && resp.status_code < 300
        ? "text-green-400"
        : resp.status_code === 0
          ? "text-red-400"
          : "text-neutral-400"
    : "";

  return (
    <div class="flex h-full flex-col">
      {/* Tab bar */}
      <div class="mb-4 flex items-center gap-0.5 overflow-x-auto border-b border-neutral-800">
        {tabs.map((tab) => (
          <button
            key={tab.meta.id}
            onClick={() => setActiveId(tab.meta.id)}
            class={`group flex items-center gap-1.5 rounded-t-md px-3 py-1.5 text-xs font-medium transition-colors ${
              tab.meta.id === activeId
                ? "bg-neutral-800 text-neutral-200"
                : "text-neutral-500 hover:bg-neutral-800/50 hover:text-neutral-300"
            }`}
          >
            <span
              contentEditable={tab.meta.id === activeId}
              suppressContentEditableWarning
              onBlur={(e) => renameTab(tab.meta.id, (e.target as HTMLSpanElement).textContent || tab.meta.name)}
              onKeyDown={(e) => {
                if (e.key === "Enter") { e.preventDefault(); (e.target as HTMLSpanElement).blur(); }
              }}
              class="max-w-[120px] truncate rounded px-0.5 outline-none focus:bg-neutral-700"
              title="Double-click to rename"
            >
              {tab.meta.name}
            </span>
            {tabs.length > 1 && (
              <span
                onClick={(e) => closeTab(tab.meta.id, e)}
                class="inline-flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded text-[10px] text-neutral-600 transition-colors hover:bg-neutral-700 hover:text-neutral-300"
              >
                ✕
              </span>
            )}
          </button>
        ))}
        <button
          onClick={addTab}
          class="flex shrink-0 items-center gap-1 rounded-t-md px-2.5 py-1.5 text-xs text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
        >
          +
        </button>
      </div>

      {/* Active tab content */}
      {activeTab && (
        <div class="grid flex-1 grid-cols-2 gap-4 min-h-0">
          {/* Request panel */}
          <div class="flex flex-col rounded-lg border border-neutral-800 bg-neutral-900">
            <div class="flex items-center justify-between border-b border-neutral-800 px-3 py-2">
              <span class="text-xs font-semibold uppercase tracking-wider text-neutral-400">Request</span>
            </div>
            <textarea
              value={activeTab.meta.raw_request}
              onInput={(e) => updateRequest(activeTab.meta.id, (e.target as HTMLTextAreaElement).value)}
              class="w-full flex-1 resize-none border-0 bg-transparent px-3 py-2 font-mono text-xs text-neutral-100 placeholder-neutral-600 focus:outline-none"
              placeholder="GET / HTTP/1.1&#10;Host: example.com&#10;"
            />
            <div class="flex items-center gap-3 border-t border-neutral-800 px-3 py-2.5">
              <button
                onClick={() => handleSend(activeTab.meta.id)}
                disabled={sending[activeTab.meta.id]}
                class="inline-flex items-center gap-2 rounded-md bg-primary-600 px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
              >
                {sending[activeTab.meta.id] ? (
                  <>
                    <svg class="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                    Sending…
                  </>
                ) : (
                  <>
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="h-3.5 w-3.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                    Send
                  </>
                )}
              </button>
              {resp && (
                <span class="text-xs text-neutral-500">{resp.timing_ms}ms</span>
              )}
            </div>
          </div>

          {/* Response panel */}
          <div class="flex flex-col rounded-lg border border-neutral-800 bg-neutral-900">
            <div class="flex items-center justify-between border-b border-neutral-800 px-3 py-2">
              <div class="flex items-center gap-3">
                <span class="text-xs font-semibold uppercase tracking-wider text-neutral-400">Response</span>
                {resp && (
                  <>
                    <span class={`text-sm font-bold ${statusClass}`}>{resp.status_code}</span>
                    <span class="text-xs text-neutral-500">{resp.timing_ms}ms</span>
                  </>
                )}
              </div>
              {resp && resp.headers?.["content-type"]?.includes("text/html") && (
                <label class="flex cursor-pointer items-center gap-1.5 text-xs text-neutral-500 select-none">
                  <input type="checkbox" checked={renderHtml} onChange={() => setRenderHtml((p) => !p)} class="accent-primary-500" />
                  Render HTML
                </label>
              )}
            </div>
            <div class="flex-1 overflow-y-auto px-3 py-2">
              {!resp ? (
                <div class="flex items-center justify-center py-16 text-sm text-neutral-600">
                  Send a request to see the response
                </div>
              ) : (
                <div class="space-y-3">
                  <details open class="rounded-md border border-neutral-800 bg-neutral-950">
                    <summary class="cursor-pointer px-3 py-2 text-xs font-semibold uppercase tracking-wider text-neutral-400">Headers</summary>
                    <div class="space-y-0.5 px-3 pb-2 pt-1">
                      {Object.entries(resp.headers).map(([k, v]) => (
                        <div class="flex gap-2 text-xs">
                          <span class="shrink-0 font-semibold text-neutral-400">{k}:</span>
                          <span class="break-all text-neutral-300">{v}</span>
                        </div>
                      ))}
                    </div>
                  </details>
                  <details open class="rounded-md border border-neutral-800 bg-neutral-950">
                    <summary class="cursor-pointer px-3 py-2 text-xs font-semibold uppercase tracking-wider text-neutral-400">Body</summary>
                    <div class="px-3 pb-2 pt-1">
                      {renderHtml && resp.headers?.["content-type"]?.includes("text/html") ? (
                        <iframe class="h-96 w-full rounded border border-neutral-700 bg-white" srcdoc={resp.body_preview} />
                      ) : (
                        <pre class="overflow-x-auto font-mono text-xs text-neutral-300 whitespace-pre-wrap">{resp.body_preview}</pre>
                      )}
                    </div>
                  </details>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

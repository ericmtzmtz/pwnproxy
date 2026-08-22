import { useMemo, useState } from "preact/hooks";
import { listTasks, pollTask } from "@/api/task/calls";

export interface HttpResponse {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  timing_ms: number;
}

interface ResponseViewerProps {
  response: HttpResponse | null;
  loading?: boolean;
}

type RespTab = "body" | "headers" | "cookies" | "render" | "diff";
type BodyMode = "pretty" | "raw" | "hex";

function statusColor(code: number): string {
  if (code >= 500) return "text-red-400";
  if (code >= 400) return "text-orange-400";
  if (code >= 300) return "text-blue-400";
  if (code >= 200) return "text-green-400";
  return "text-neutral-400";
}

function statusText(code: number): string {
  if (code === 0) return "No response";
  const map: Record<number, string> = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error",
    502: "Bad Gateway", 503: "Service Unavailable",
  };
  return map[code] ?? "Status";
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function toHex(s: string): string {
  const lines: string[] = [];
  for (let i = 0; i < s.length; i += 16) {
    const chunk = s.slice(i, i + 16);
    const hex = [...chunk].map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
    const ascii = [...chunk].map((c) => (c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127 ? c : ".")).join("");
    lines.push(`${i.toString(16).padStart(6, "0")}  ${hex.padEnd(48)}  ${ascii}`);
  }
  return lines.join("\n");
}

function prettyBody(body: string, ct: string): string {
  if (ct.includes("json")) {
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch { /* fall through */ }
  }
  if (ct.includes("xml")) {
    // naive indent — real formatting would need a parser; keep raw for now
    return body;
  }
  return body;
}

function highlightBody(body: string, ct: string): string {
  const esc = body.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  if (ct.includes("json")) {
    // highlight keys and strings crudely
    return esc.replace(/"([^"]+)":/g, '<span class="text-sky-400">"$1"</span>:');
  }
  return esc;
}

// --- Diff ---

interface DiffItem {
  id: string;
  status: number;
  method: string;
  url: string;
  body: string;
}

interface DiffPanelProps {
  current: string;
  currentStatus: number;
  onLoadHistory: () => Promise<void>;
  history: DiffItem[];
  historyLoading: boolean;
  diffWith: string | null;
  onPick: (id: string) => void;
  diffMode: "line" | "char";
  onDiffMode: (m: "line" | "char") => void;
}

/** Simple LCS-based line diff. Returns ops per line: eq/del/ins. */
function lineDiff(a: string[], b: string[]): { a: string; b: string; type: "eq" | "del" | "ins" }[] {
  const n = a.length;
  const m = b.length;
  // DP table for LCS lengths
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: { a: string; b: string; type: "eq" | "del" | "ins" }[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ a: a[i], b: b[j], type: "eq" });
      i++; j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ a: a[i], b: "", type: "del" });
      i++;
    } else {
      out.push({ a: "", b: b[j], type: "ins" });
      j++;
    }
  }
  while (i < n) { out.push({ a: a[i], b: "", type: "del" }); i++; }
  while (j < m) { out.push({ a: "", b: b[j], type: "ins" }); j++; }
  return out;
}

function DiffPanel({ current, currentStatus, onLoadHistory, history, historyLoading, diffWith, onPick, diffMode, onDiffMode }: DiffPanelProps) {
  const selected = history.find((h) => h.id === diffWith) ?? null;

  const diffRows = useMemo(() => {
    if (!selected) return [];
    return lineDiff((selected.body ?? "").split("\n"), current.split("\n"));
  }, [selected, current]);

  if (historyLoading) {
    return <div class="p-3 text-xs text-neutral-500">Loading history…</div>;
  }

  return (
    <div class="flex h-full flex-col">
      {/* Controls */}
      <div class="flex items-center gap-2 border-b border-neutral-800 px-3 py-2">
        <button
          onClick={onLoadHistory}
          class="rounded border border-neutral-800 px-2 py-0.5 text-[11px] text-neutral-400 hover:bg-neutral-800 hover:text-neutral-200"
        >
          Load History
        </button>
        <select
          value={diffWith ?? ""}
          onChange={(e) => onPick((e.target as HTMLSelectElement).value)}
          class="flex-1 rounded border border-neutral-800 bg-neutral-900 px-2 py-0.5 text-[11px] text-neutral-300 outline-none"
        >
          <option value="">— select a previous response —</option>
          {history.map((h) => (
            <option key={h.id} value={h.id}>{h.method} {h.url.slice(0, 60)} ({h.status})</option>
          ))}
        </select>
        <div class="flex gap-0.5">
          {(["line", "char"] as const).map((m) => (
            <button
              key={m}
              onClick={() => onDiffMode(m)}
              class={`rounded px-2 py-0.5 text-[10px] font-medium capitalize ${diffMode === m ? "bg-neutral-700 text-neutral-200" : "text-neutral-500 hover:text-neutral-300"}`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      {!selected ? (
        <div class="p-3 text-xs text-neutral-600">
          Load history and pick a previous response to compare against the current one.
        </div>
      ) : (
        <div class="min-h-0 flex-1 overflow-auto">
          <div class="sticky top-0 z-10 flex items-center gap-3 border-b border-neutral-800 bg-neutral-950 px-3 py-1 text-[10px]">
            <span class="text-neutral-500">← {selected.method} {selected.status}</span>
            <span class="text-neutral-600">vs</span>
            <span class="text-neutral-300">current {currentStatus}</span>
          </div>
          {diffMode === "line" ? (
            <table class="w-full border-collapse font-mono text-[11px]">
              <tbody>
                {diffRows.map((row, idx) => (
                  <tr key={idx} class={
                    row.type === "del" ? "bg-red-950/40" : row.type === "ins" ? "bg-green-950/40" : ""
                  }>
                    <td class="w-10 select-none border-r border-neutral-800 px-2 text-right text-neutral-700">
                      {row.type === "del" ? row.a : ""}
                    </td>
                    <td class="px-2 text-neutral-200">
                      {row.type === "del" && <span class="text-red-400">- {row.a}</span>}
                      {row.type === "ins" && <span class="text-green-400">+ {row.b}</span>}
                      {row.type === "eq" && <span class="text-neutral-500">{row.a}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <pre class="p-3 font-mono text-[11px] leading-relaxed">
              <span class="text-red-400">- {selected.body}</span>
              {"\n"}
              <span class="text-green-400">+ {current}</span>
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export function ResponseViewer({ response, loading }: ResponseViewerProps) {
  const [tab, setTab] = useState<RespTab>("body");
  const [bodyMode, setBodyMode] = useState<BodyMode>("pretty");
  const [renderHtml, setRenderHtml] = useState(false);
  const [history, setHistory] = useState<{ id: string; status: number; method: string; url: string; body: string }[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [diffWith, setDiffWith] = useState<string | null>(null);
  const [diffMode, setDiffMode] = useState<"line" | "char">("line");

  const ct = response?.headers?.["content-type"] ?? "";
  const isHtml = ct.includes("text/html");

  const metrics = useMemo(() => {
    if (!response) return null;
    const size = response.body?.length ?? 0;
    return {
      code: response.status_code,
      time: response.timing_ms,
      size,
      sizeLabel: formatSize(size),
      lines: (response.body ?? "").split("\n").length,
    };
  }, [response]);

  if (loading) {
    return (
      <div class="flex items-center justify-center py-16 text-sm text-neutral-500">
        <svg class="mr-2 h-4 w-4 animate-spin text-primary-400" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
        Sending…
      </div>
    );
  }

  if (!response) {
    return (
      <div class="flex items-center justify-center py-16 text-sm text-neutral-600">
        Send a request to see the response
      </div>
    );
  }

  const tabs: { id: RespTab; label: string; count?: number }[] = [
    { id: "body", label: "Body" },
    { id: "headers", label: "Headers", count: Object.keys(response.headers).length },
    { id: "cookies", label: "Cookies", count: Object.keys(response.headers).filter((h) => h.toLowerCase() === "set-cookie").length },
    ...(isHtml ? [{ id: "render" as RespTab, label: "Render" }] : []),
    { id: "diff", label: "Diff" },
  ];

  return (
    <div class="flex h-full flex-col">
      {/* Metrics bar */}
      {metrics && (
        <div class="flex items-center gap-3 border-b border-neutral-800 px-3 py-1.5 text-xs">
          <span class={`font-bold ${statusColor(metrics.code)}`}>
            {metrics.code === 0 ? "✗" : "✓"} {metrics.code > 0 ? `${metrics.code} ${statusText(metrics.code)}` : "No response"}
          </span>
          <span class="text-neutral-500">{metrics.time} ms</span>
          <span class="text-neutral-500">{metrics.sizeLabel}</span>
          <span class="text-neutral-600">{metrics.lines} lines</span>
        </div>
      )}

      {/* Response tabs */}
      <div class="flex items-center gap-0.5 border-b border-neutral-800 px-2 pt-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            class={`rounded-t px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
              tab === t.id ? "bg-neutral-800 text-neutral-200" : "text-neutral-500 hover:text-neutral-300"
            }`}
          >
            {t.label}
            {t.count !== undefined && t.count > 0 && (
              <span class="ml-1 text-[10px] text-neutral-500">({t.count})</span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div class="min-h-0 flex-1 overflow-y-auto">
        {tab === "body" && (
          <div class="flex h-full flex-col">
            <div class="flex items-center gap-1 border-b border-neutral-800 px-2 py-1">
              {(["pretty", "raw", "hex"] as BodyMode[]).map((m) => (
                <button
                  key={m}
                  onClick={() => setBodyMode(m)}
                  class={`rounded px-2 py-0.5 text-[10px] font-medium capitalize transition-colors ${
                    bodyMode === m ? "bg-neutral-700 text-neutral-200" : "text-neutral-500 hover:text-neutral-300"
                  }`}
                >
                  {m}
                </button>
              ))}
              {isHtml && (
                <label class="ml-auto flex cursor-pointer items-center gap-1 text-[10px] text-neutral-500 select-none">
                  <input type="checkbox" checked={renderHtml} onChange={() => setRenderHtml((p) => !p)} class="accent-primary-500" />
                  Render HTML
                </label>
              )}
            </div>
            {bodyMode === "hex" ? (
              <pre class="flex-1 overflow-auto p-3 font-mono text-[11px] leading-relaxed text-neutral-300">{toHex(response.body ?? "")}</pre>
            ) : bodyMode === "raw" || (bodyMode === "pretty" && !ct.includes("json")) ? (
              <pre class="flex-1 overflow-auto whitespace-pre-wrap p-3 font-mono text-[11px] leading-relaxed text-neutral-300">{response.body}</pre>
            ) : (
              <pre class="flex-1 overflow-auto whitespace-pre-wrap p-3 font-mono text-[11px] leading-relaxed text-neutral-300" dangerouslySetInnerHTML={{ __html: highlightBody(prettyBody(response.body ?? "", ct), ct) }} />
            )}
          </div>
        )}

        {tab === "headers" && (
          <div class="p-3">
            <div class="space-y-0.5">
              {Object.entries(response.headers).map(([k, v]) => (
                <div class="flex gap-2 text-xs">
                  <span class="shrink-0 font-semibold text-neutral-400">{k}:</span>
                  <span class="break-all text-neutral-300">{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === "cookies" && (
          <div class="p-3">
            {Object.entries(response.headers)
              .filter(([k]) => k.toLowerCase() === "set-cookie")
              .map(([k, v]) => (
                <div class="mb-2 rounded border border-neutral-800 bg-neutral-950 p-2">
                  <div class="text-xs font-semibold text-neutral-400">Set-Cookie</div>
                  <div class="mt-1 break-all font-mono text-xs text-neutral-300">{v}</div>
                </div>
              ))}
            {!Object.keys(response.headers).some((k) => k.toLowerCase() === "set-cookie") && (
              <div class="text-xs text-neutral-600">No cookies in response</div>
            )}
          </div>
        )}

        {tab === "render" && isHtml && (
          <iframe class="h-full w-full border-0 bg-white" srcDoc={response.body} />
        )}

        {tab === "diff" && (
          <DiffPanel
            current={response.body ?? ""}
            currentStatus={response.status_code}
            onLoadHistory={async () => {
              setHistoryLoading(true);
              try {
                const data = await listTasks("repeater", 50);
                const out: typeof history = [];
                for (const t of data.tasks ?? []) {
                  try {
                    const full = await pollTask(t.id);
                    const r = full.result;
                    if (r && r.body !== undefined) {
                      const raw = (full.config?.raw_request as string) ?? "";
                      const m = raw.trim().match(/^(\w+)/);
                      const urlM = raw.match(/^\w+\s+(\S+)/);
                      out.push({
                        id: t.id,
                        status: (r.status_code as number) ?? 0,
                        method: m ? m[1].toUpperCase() : "GET",
                        url: urlM ? urlM[1] : "",
                        body: (r.body as string) ?? "",
                      });
                    }
                  } catch { /* skip task */ }
                }
                setHistory(out);
              } catch { /* api down */ } finally {
                setHistoryLoading(false);
              }
            }}
            history={history}
            historyLoading={historyLoading}
            diffWith={diffWith}
            onPick={(id) => setDiffWith(id)}
            diffMode={diffMode}
            onDiffMode={(m) => setDiffMode(m)}
          />
        )}
      </div>
    </div>
  );
}

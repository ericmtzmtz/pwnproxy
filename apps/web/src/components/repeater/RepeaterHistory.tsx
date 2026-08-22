import { useEffect, useMemo, useState } from "preact/hooks";
import { listTasks, pollTask } from "@/api/task/calls";

interface RepeaterHistoryProps {
  onRestore: (raw: string, name: string) => void;
  onClose: () => void;
}

interface HistoryItem {
  task_id: string;
  raw: string;
  method: string;
  url: string;
  status_code: number | null;
  timing_ms: number | null;
  created_at: string;
}

function methodFromRaw(raw: string): string {
  const m = raw.trim().match(/^(\w+)/);
  return m ? m[1].toUpperCase() : "GET";
}

function urlFromRaw(raw: string): string {
  const m = raw.trim().match(/^\w+\s+(\S+)/);
  if (!m) return "";
  const path = m[1];
  const hostMatch = raw.match(/^Host:\s*(\S+)/im);
  const host = hostMatch ? hostMatch[1] : "";
  return host ? `${host}${path}` : path;
}

function statusColor(code: number | null): string {
  if (code === null || code === 0) return "text-neutral-600";
  if (code >= 500) return "text-red-400";
  if (code >= 400) return "text-orange-400";
  if (code >= 300) return "text-blue-400";
  if (code >= 200) return "text-green-400";
  return "text-neutral-400";
}

export function RepeaterHistory({ onRestore, onClose }: RepeaterHistoryProps) {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const data = await listTasks("repeater", 100);
        const tasks = data.tasks ?? [];
        const mapped: HistoryItem[] = [];
        for (const t of tasks) {
          const raw = (t.config?.raw_request as string) ?? "";
          if (!raw) continue;
          let status: number | null = null;
          let timing: number | null = null;
          const r = t.result as Record<string, unknown> | null;
          if (r && r.status_code !== undefined) {
            status = r.status_code as number;
            timing = (r.duration_ms as number) ?? null;
          }
          mapped.push({
            task_id: t.id,
            raw,
            method: methodFromRaw(raw),
            url: urlFromRaw(raw),
            status_code: status,
            timing_ms: timing,
            created_at: t.created_at ?? "",
          });
        }
        setItems(mapped);
      } catch { /* API down */ } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered = useMemo(() => {
    return items.filter((i) => {
      if (search && !i.url.toLowerCase().includes(search.toLowerCase()) && !i.raw.toLowerCase().includes(search.toLowerCase())) return false;
      if (methodFilter && i.method !== methodFilter) return false;
      if (statusFilter) {
        const bucket = i.status_code === null ? "none" : String(i.status_code)[0] + "xx";
        if (bucket !== statusFilter) return false;
      }
      return true;
    });
  }, [items, search, methodFilter, statusFilter]);

  return (
    <div class="flex w-80 shrink-0 flex-col border-l border-neutral-800 bg-neutral-950">
      <div class="flex items-center justify-between border-b border-neutral-800 px-3 py-2">
        <span class="text-xs font-semibold uppercase tracking-wider text-neutral-400">History ({items.length})</span>
        <button onClick={onClose} class="rounded px-1.5 text-xs text-neutral-500 hover:bg-neutral-800 hover:text-neutral-300">✕</button>
      </div>

      {/* Filters */}
      <div class="space-y-1.5 border-b border-neutral-800 px-3 py-2">
        <input
          value={search}
          onInput={(e) => setSearch((e.target as HTMLInputElement).value)}
          placeholder="Search URL…"
          class="w-full rounded border border-neutral-800 bg-neutral-900 px-2 py-1 text-[11px] text-neutral-200 outline-none placeholder:text-neutral-600 focus:border-primary-700"
        />
        <div class="flex gap-1.5">
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter((e.target as HTMLSelectElement).value)}
            class="flex-1 rounded border border-neutral-800 bg-neutral-900 px-1.5 py-1 text-[11px] text-neutral-300 outline-none"
          >
            <option value="">All methods</option>
            {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter((e.target as HTMLSelectElement).value)}
            class="flex-1 rounded border border-neutral-800 bg-neutral-900 px-1.5 py-1 text-[11px] text-neutral-300 outline-none"
          >
            <option value="">All status</option>
            {["2xx", "3xx", "4xx", "5xx", "none"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
      </div>

      {/* List */}
      <div class="min-h-0 flex-1 overflow-y-auto">
        {loading ? (
          <div class="px-3 py-4 text-xs text-neutral-600">Loading…</div>
        ) : filtered.length === 0 ? (
          <div class="px-3 py-4 text-xs text-neutral-600">No requests in history yet.</div>
        ) : (
          filtered.map((item) => (
            <button
              key={item.task_id}
              onClick={() => onRestore(item.raw, `${item.method} ${item.url.slice(0, 40)}`)}
              class="block w-full border-b border-neutral-800/50 px-3 py-2 text-left transition-colors hover:bg-neutral-800/50"
              title="Click to restore as new tab"
            >
              <div class="flex items-center gap-2">
                <span class="text-[10px] font-semibold text-sky-400">{item.method}</span>
                {item.status_code !== null && (
                  <span class={`text-[10px] font-bold ${statusColor(item.status_code)}`}>{item.status_code}</span>
                )}
                {item.timing_ms !== null && <span class="text-[10px] text-neutral-600">{item.timing_ms}ms</span>}
              </div>
              <div class="mt-0.5 truncate font-mono text-[10px] text-neutral-400">{item.url}</div>
            </button>
          ))
        )}
      </div>
    </div>
  );
}

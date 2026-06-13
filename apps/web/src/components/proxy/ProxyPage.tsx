import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import { FlowTable } from "./FlowTable";
import { useWebSocket } from "@/hooks/useWebSocket";
import { listFlows, clearFlows } from "@/api/traffic/calls";
import { getProxyStatus, startProxy, stopProxy, toggleProxy } from "@/api/proxy/calls";
import type { FlowRecord } from "@/api/traffic/types";

const API_BASE = import.meta.env.PUBLIC_API_BASE ?? "http://127.0.0.1:8000/api/v1";
const PAGE_SIZE = 20;
const METHODS = ["", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export function ProxyPage() {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsMap, setFindingsMap] = useState<Record<number, number>>({});
  const [captureEnabled, setCaptureEnabled] = useState(true);
  const [proxyRunning, setProxyRunning] = useState<boolean | null>(null);
  const [page, setPage] = useState(0);
  const [methodFilter, setMethodFilter] = useState("");
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const maxFlowIdRef = useRef(0);
  const wsConnectedRef = useRef(false);
  const loadedRef = useRef(false);

  const filtered = methodFilter
    ? flows.filter((f) => f.method === methodFilter)
    : flows;
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const pagedFlows = filtered.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE);

  const count1xx = flows.filter((f) => f.status_code && f.status_code >= 100 && f.status_code < 200).length;
  const count2xx = flows.filter((f) => f.status_code && f.status_code >= 200 && f.status_code < 300).length;
  const count3xx = flows.filter((f) => f.status_code && f.status_code >= 300 && f.status_code < 400).length;
  const countErr = flows.filter((f) => f.status_code && (f.status_code >= 400 || f.error)).length;

  const buildFindingsMap = useCallback((ff: Finding[]) => {
    const map: Record<number, number> = {};
    for (const f of ff) {
      const match = flows.find((fl) => fl.url === f.url && fl.method === f.method);
      if (match) {
        map[match.id] = (map[match.id] ?? 0) + 1;
      }
    }
    setFindingsMap(map);
  }, [flows]);

  const loadInitialData = useCallback(async () => {
    try {
      const flowData = await listFlows(100, 0);
      setFlows(flowData);
      if (flowData.length > 0) {
        maxFlowIdRef.current = Math.max(...flowData.map((f) => f.id));
      }
      const status = await getProxyStatus();
      setCaptureEnabled(status.capture_enabled);
      setProxyRunning(status.running);
    } catch { /* silent */ }
  }, []);

  const startPolling = useCallback(() => {
    if (pollTimerRef.current) return;
    pollTimerRef.current = setInterval(async () => {
      try {
        if (maxFlowIdRef.current > 0) {
          const newFlows = await (await fetch(
            `${API_BASE}/flows?since_id=${maxFlowIdRef.current}`,
          )).json();
          if (newFlows.length > 0) {
            setFlows((prev) => [...newFlows, ...prev].slice(0, 200));
            maxFlowIdRef.current = Math.max(...newFlows.map((f: FlowRecord) => f.id));
          }
        }
      } catch { /* silent */ }
    }, 3000);
  }, []);

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) {
      clearInterval(pollTimerRef.current);
      pollTimerRef.current = null;
    }
  }, []);

  const onWsMessage = useCallback(
    (msg: { type: string; [key: string]: unknown }) => {
      wsConnectedRef.current = true;
      stopPolling();

      if (msg.type === "flow") {
        const f = msg as unknown as FlowRecord;
        setFlows((prev) => {
          if (prev.some((p) => p.id === f.id)) return prev;
          return [f, ...prev].slice(0, 200);
        });
        if (f.id > maxFlowIdRef.current) maxFlowIdRef.current = f.id;
      } else if (msg.type === "finding") {
        const finding = msg as unknown as Finding;
        setFindings((prev) => {
          if (prev.some((p) => p.scanner === finding.scanner && p.id === finding.id)) return prev;
          return [finding, ...prev].slice(0, 200);
        });
      }
    },
    [stopPolling],
  );

  const { connected } = useWebSocket({
    url: `ws://${new URL(API_BASE).host}/ws/events`,
    onMessage: onWsMessage,
  });

  useEffect(() => {
    if (!connected && loadedRef.current && !wsConnectedRef.current) {
      startPolling();
    } else {
      stopPolling();
    }
  }, [connected, startPolling, stopPolling]);

  if (!loadedRef.current) {
    loadedRef.current = true;
    loadInitialData();
  }

  useEffect(() => {
    buildFindingsMap(findings);
  }, [findings, buildFindingsMap]);

  useEffect(() => {
    setPage(0);
  }, [methodFilter]);

  useEffect(() => {
    const t = setInterval(async () => {
      try {
        const status = await getProxyStatus();
        setCaptureEnabled(status.capture_enabled);
        setProxyRunning(status.running);
      } catch { /* silent */ }
    }, 5000);
    return () => clearInterval(t);
  }, []);

  const handleClear = async () => {
    try {
      await clearFlows();
    } catch { /* silent */ }
    setFlows([]);
    setFindings([]);
    setFindingsMap({});
    maxFlowIdRef.current = 0;
    setPage(0);
  };

  const handleDeleted = (id: number) => {
    setFlows((prev) => prev.filter((f) => f.id !== id));
  };

  return (
    <div>
      <div class="mb-6 flex items-center justify-between">
        <div>
          <h1 class="text-xl font-bold text-neutral-50">Proxy Traffic</h1>
          <p class="mt-0.5 text-sm text-neutral-400">Live HTTP traffic intercepted by the proxy</p>
        </div>
        <div class="flex items-center gap-3">
          <span class="flex items-center gap-1.5 text-xs text-neutral-500">
            <span class={`inline-flex h-2 w-2 rounded-full ${connected ? "bg-success-500" : "bg-yellow-500"}`} />
            Listening on 127.0.0.1:8080
          </span>
          <button
            onClick={async () => {
              try {
                const status = await toggleProxy();
                setCaptureEnabled(status.capture_enabled);
              } catch { /* silent */ }
            }}
            class={`cursor-pointer rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
              captureEnabled
                ? "border-success-800 bg-success-900/20 text-success-400 hover:bg-success-900/40"
                : "border-neutral-700 bg-neutral-800 text-neutral-400 hover:bg-neutral-700"
            }`}
            title={captureEnabled ? "Pause traffic capture" : "Resume traffic capture"}
          >
            <span class="inline-flex items-center gap-1.5">
              <span class={`inline-flex h-2 w-2 rounded-full ${captureEnabled ? "bg-success-500" : "bg-neutral-500"}`} />
              {captureEnabled ? "Capturing" : "Paused"}
            </span>
          </button>
          <button
            onClick={handleClear}
            class="rounded-md border border-neutral-700 px-2.5 py-1 text-xs font-medium text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-200"
          >
            Clear
          </button>
        </div>
      </div>

      <div class="mb-4 flex items-center justify-between rounded-lg border border-neutral-800 bg-neutral-900 px-4 py-3">
        <div class="flex items-center gap-3">
          <span class="flex items-center gap-2 text-sm font-medium text-neutral-50">
            <span class={`inline-flex h-2.5 w-2.5 rounded-full ${proxyRunning === null ? "bg-yellow-500" : proxyRunning ? "bg-success-500" : "bg-danger-500"}`} />
            Proxy
          </span>
          <span class="text-sm text-neutral-400">
            {proxyRunning === null ? "Checking..." : proxyRunning ? "Running on 127.0.0.1:8080" : "Stopped"}
          </span>
        </div>
        <div class="flex items-center gap-2">
          {proxyRunning ? (
            <button
              onClick={async () => { await stopProxy(); setProxyRunning(false); }}
              class="cursor-pointer rounded-md border border-danger-800 bg-danger-900/20 px-3 py-1 text-xs font-medium text-danger-400 transition-colors hover:bg-danger-900/40"
            >
              Stop
            </button>
          ) : (
            <button
              onClick={async () => { const s = await startProxy(); setProxyRunning(s.running); }}
              class="cursor-pointer rounded-md border border-success-800 bg-success-900/20 px-3 py-1 text-xs font-medium text-success-400 transition-colors hover:bg-success-900/40"
            >
              Start
            </button>
          )}
        </div>
      </div>

      <div class="grid grid-cols-5 gap-3">
        <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
          <span class="text-xs text-neutral-500">Total Flows</span>
          <p class="mt-0.5 text-lg font-bold text-neutral-50">{flows.length}</p>
        </div>
        <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
          <span class="text-xs text-neutral-500">2xx</span>
          <p class="mt-0.5 text-lg font-bold text-success-500">{count2xx}</p>
        </div>
        <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
          <span class="text-xs text-neutral-500">3xx</span>
          <p class="mt-0.5 text-lg font-bold text-blue-400">{count3xx}</p>
        </div>
        <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
          <span class="text-xs text-neutral-500">1xx</span>
          <p class="mt-0.5 text-lg font-bold text-neutral-400">{count1xx}</p>
        </div>
        <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
          <span class="text-xs text-neutral-500">4xx/5xx</span>
          <p class="mt-0.5 text-lg font-bold text-danger-500">{countErr}</p>
        </div>
      </div>

      <div class="mt-4 flex items-center justify-between">
        <div class="flex items-center gap-1">
          {METHODS.map((m) => (
            <button
              key={m}
              onClick={() => setMethodFilter(m)}
              class={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                methodFilter === m
                  ? "bg-primary-600 text-white"
                  : "bg-neutral-800 text-neutral-400 hover:bg-neutral-700"
              }`}
            >
              {m || "All"}
            </button>
          ))}
        </div>
        {totalPages > 1 && (
          <div class="flex items-center gap-2 text-xs text-neutral-400">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={safePage === 0}
              class="rounded px-2 py-1 disabled:opacity-30 hover:bg-neutral-800"
            >
              ← Prev
            </button>
            <span>{safePage + 1} / {totalPages}</span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={safePage >= totalPages - 1}
              class="rounded px-2 py-1 disabled:opacity-30 hover:bg-neutral-800"
            >
              Next →
            </button>
          </div>
        )}
      </div>

      <div class="mt-2">
        <FlowTable flows={pagedFlows} findingsMap={findingsMap} onAutoScrolled={() => {}} onDeleted={handleDeleted} />
      </div>
    </div>
  );
}

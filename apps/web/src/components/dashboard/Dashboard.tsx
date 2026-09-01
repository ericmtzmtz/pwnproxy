import { useEffect, useRef, useState } from "preact/hooks";
import { StatCards } from "./StatCards";
import { FindingsSection } from "./FindingsSection";
import { DiscoveredSection } from "./DiscoveredSection";
import { listFlows } from "@/api/traffic/calls";
import { listFindings } from "@/api/findings/calls";
import { formatTimeOnly } from "@/utils/formatTimestamp";
import type { FlowRecord } from "@/api/traffic/types";
import type { Finding } from "@/api/findings/types";

export function Dashboard() {
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [totalFindings, setTotalFindings] = useState(0);
  const loadedRef = useRef(false);

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;
  const infoCount = findings.filter((f) =>f.severity === "info").length;

  const recentFlows = flows.slice(0, 5);

  useEffect(() => {
    if (loadedRef.current) return;
    loadedRef.current = true;
    listFlows(100, 0).then(setFlows).catch(() => {});
    listFindings(1, 500).then((r) => {
      setTotalFindings(r.total);
      setFindings(r.items);
    }).catch(() => {});
  }, []);

  return (
    <div>
      <div class="mb-6">
        <h1 class="text-xl font-bold text-neutral-50">Dashboard</h1>
        <p class="mt-0.5 text-sm text-neutral-400">Security metrics overview</p>
      </div>

      <StatCards
        flowsCount={flows.length}
        findingsCount={totalFindings}
        criticalCount={criticalCount}
        highCount={highCount}
        mediumCount={mediumCount}
        lowCount={lowCount}
        infoCount={infoCount}
        scannerCount={5}
        scopeCount={0}
      />

      <div class="mt-8">
        <FindingsSection liveFindings={findings} />
      </div>

      <div class="mt-8">
        <DiscoveredSection />
      </div>

      {recentFlows.length > 0 && (
        <div class="mt-6">
          <h2 class="mb-3 text-sm font-semibold text-neutral-200">Recent Activity</h2>
          <div class="space-y-1">
            {recentFlows.map((f) => (
              <div
                key={f.id}
                class="flex items-center gap-3 rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-xs"
              >
                <span class="w-16 shrink-0 text-neutral-500">{formatTimeOnly(f.timestamp)}</span>
                <span class={`w-12 shrink-0 font-semibold ${
                  f.status_code && f.status_code >= 400 ? "text-danger-500" : f.status_code && f.status_code >= 200 ? "text-success-500" : "text-neutral-400"
                }`}>
                  {f.status_code ?? "—"}
                </span>
                <span class="w-12 shrink-0 font-semibold uppercase text-neutral-400">{f.method}</span>
                <span class="min-w-0 truncate text-neutral-300">{f.url}</span>
                {f.tls && <span class="shrink-0 text-[10px] text-green-500">HTTPS</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

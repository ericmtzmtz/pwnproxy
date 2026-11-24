import { useEffect, useState } from "preact/hooks";
import { getWorkers, type WorkersResponse } from "@/api/workers/calls";

function PulsingDot({ color }: { color: string }) {
  return (
    <span class="relative inline-flex h-2 w-2">
      <span class={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${color}`} />
      <span class={`relative inline-flex h-2 w-2 rounded-full ${color}`} />
    </span>
  );
}

function Chip({
  label,
  detail,
  busy,
  paused = false,
  title,
}: {
  label: string;
  detail: string;
  busy: boolean;
  paused?: boolean;
  title?: string;
}) {
  const tone = paused
    ? "border-warning-800/60 bg-warning-900/30"
    : busy
      ? "border-blue-800/60 bg-blue-900/30"
      : "border-neutral-800 bg-neutral-900";
  const labelTone = paused ? "text-warning-300" : busy ? "text-blue-300" : "text-neutral-500";
  return (
    <span
      class={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${tone}`}
      title={title}
    >
      {busy && <PulsingDot color="bg-blue-400" />}
      <span class={labelTone}>{label}</span>
      <span class="font-mono text-[10px] text-neutral-400">{detail}</span>
    </span>
  );
}

export function WorkersStrip() {
  const [data, setData] = useState<WorkersResponse | null>(null);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const d = await getWorkers();
        if (alive) setData(d);
      } catch {
        /* backend not reachable yet */
      }
    };
    poll();
    const timer = setInterval(poll, 2000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  if (!data) return null;

  const activeTasks = data.tasks.filter((t) => t.status === "running" || t.status === "queued");
  const crawlerBusy = data.crawler_jobs.length > 0;
  const proxyBusy = data.proxy.running && data.proxy.capture_enabled;
  // The backend decides: `false` means the auto-scan receives nothing. The
  // strip only shows the verdict and the sentence it publishes.
  const scanPaused = data.active_scan_allowed === false;
  const pauseReason = data.active_scan_blocked_reason ?? "";

  return (
    <div class="flex flex-wrap items-center gap-2 rounded-lg border border-neutral-800 bg-neutral-950 px-3 py-2">
      <span class="text-[10px] font-semibold uppercase tracking-wider text-neutral-500">Workers</span>
      <Chip
        label="Proxy"
        detail={data.proxy.running ? `:${data.proxy.port}` : "off"}
        busy={proxyBusy}
      />
      <Chip
        label="Crawler"
        detail={crawlerBusy ? `${data.crawler_jobs.length} job(s)` : "idle"}
        busy={crawlerBusy}
      />
      <Chip
        label="Tasks"
        detail={activeTasks.length > 0 ? activeTasks.map((t) => `${t.type}(${t.progress}/${t.total || "?"})`).join(", ") : "none"}
        busy={activeTasks.length > 0}
      />
      <Chip
        label="Auto-scan"
        detail={
          scanPaused
            ? "paused"
            : data.autoscan.running && data.autoscan.active
              ? `${data.autoscan.active.flows} flows, ${data.autoscan.active.findings} findings`
              : data.autoscan.last
                ? `last: ${data.autoscan.last.flows} flows, ${data.autoscan.last.findings} findings`
                : "idle"
        }
        busy={!scanPaused && data.autoscan.running}
        paused={scanPaused}
        title={scanPaused ? pauseReason : undefined}
      />
      {scanPaused ? (
        <p role="status" class="w-full text-[11px] font-medium text-warning-300">
          {pauseReason}
        </p>
      ) : null}
    </div>
  );
}

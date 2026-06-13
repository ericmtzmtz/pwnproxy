import { useEffect, useRef, useState } from "preact/hooks";
import { pollTask } from "@/api/task/calls";
import type { TaskStatus } from "@/api/task/types";

interface TaskPollerProps {
  taskId: string;
  onComplete?: (task: TaskStatus) => void;
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

function findingRow(f: any, i: number) {
  const isConfirmed = f.confidence === "confirmed";
  return (
    <tr key={i} class="bg-neutral-950 hover:bg-neutral-900/50">
      <td class={`px-3 py-2 text-xs font-semibold ${sevColor(f.severity)}`}>{f.severity}</td>
      <td class="px-3 py-2 font-mono text-xs uppercase text-neutral-300">{f.scanner}</td>
      <td class="max-w-[300px] truncate px-3 py-2 text-xs text-neutral-400" title={f.url}>{f.url}</td>
      <td class="px-3 py-2 font-mono text-xs text-neutral-300">{f.param_name || "-"}</td>
      <td class="px-3 py-2">
        <span class={`inline-flex items-center rounded-full ${isConfirmed ? "bg-red-900/40 text-red-400" : "bg-yellow-900/40 text-yellow-400"} px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider`}>
          {f.confidence}
        </span>
      </td>
      <td class="max-w-[200px] truncate px-3 py-2 font-mono text-xs text-neutral-400" title={f.payload}>{f.payload || "-"}</td>
    </tr>
  );
}

function intruderResultRow(r: any, i: number) {
  const sc = r.status_code >= 400 ? "text-danger-500" : r.status_code >= 200 && r.status_code < 300 ? "text-success-500" : "text-neutral-500";
  return (
    <tr key={i} class="bg-neutral-950 hover:bg-neutral-900/50">
      <td class="px-2 py-1.5 text-xs text-neutral-500">{r.request_id}</td>
      <td class="max-w-[150px] truncate px-2 py-1.5 font-mono text-xs text-neutral-300">{r.payload}</td>
      <td class={`px-2 py-1.5 text-xs font-semibold ${sc}`}>{r.status_code}</td>
      <td class="px-2 py-1.5 text-xs text-neutral-400">{r.response_length}</td>
      <td class="px-2 py-1.5 text-xs text-neutral-500">{r.timing_ms?.toFixed(0)}ms</td>
    </tr>
  );
}

export function TaskPoller({ taskId, onComplete }: TaskPollerProps) {
  const [task, setTask] = useState<TaskStatus | null>(null);
  const [done, setDone] = useState(false);
  const calledRef = useRef(false);

  useEffect(() => {
    let active = true;
    calledRef.current = false;

    const tick = async () => {
      try {
        const t = await pollTask(taskId);
        if (!active) return;
        setTask(t);

        if (t.status === "completed" || t.status === "failed" || t.status === "cancelled") {
          setDone(true);
          if (!calledRef.current) {
            calledRef.current = true;
            window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
              detail: {
                title: `${t.type} ${t.status}`,
                message: t.error ?? `${t.type} finished (${t.progress}/${t.total})`,
                severity: t.status === "completed" ? (t.result?.findings?.length > 0 ? "warning" : "success") : "error",
              },
            }));
            onComplete?.(t);
          }
        }
      } catch {
        if (active) setTimeout(tick, 1000);
      }
    };

    tick();
    const interval = setInterval(tick, 1000);
    return () => { active = false; clearInterval(interval); };
  }, [taskId]);

  if (!task) {
    return (
      <div class="flex items-center justify-center py-8">
        <svg class="h-6 w-6 animate-spin text-primary-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" /><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
        <span class="ml-2 text-sm text-neutral-400">Starting...</span>
      </div>
    );
  }

  if (!done && task.status === "running") {
    return (
      <div class="flex items-center justify-center py-8">
        <svg class="h-6 w-6 animate-spin text-primary-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" /><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
        <span class="ml-2 text-sm text-neutral-400">
          {task.type === "intruder" ? `${task.progress} / ${task.total} requests` : `${task.type}...`}
        </span>
      </div>
    );
  }

  if (task.status === "failed") {
    return (
      <div class="rounded-lg border border-red-800 bg-red-900/20 p-4">
        <p class="text-sm font-medium text-danger-500">Failed</p>
        <p class="mt-1 text-xs text-neutral-400">{task.error}</p>
      </div>
    );
  }

  if (task.type === "scan" && task.result?.findings) {
    return <ScanResults findings={task.result.findings} />;
  }

  if (task.type === "intruder" && task.result?.results) {
    return <IntruderResults results={task.result.results} total={task.total} />;
  }

  if (task.type === "repeater" && task.result) {
    return <RepeaterResult result={task.result as any} />;
  }

  return (
    <div class="flex flex-col items-center justify-center py-12 text-sm text-neutral-600">
      <p>{task.type} {task.status}</p>
    </div>
  );
}

function ScanResults({ findings }: { findings: any[] }) {
  if (!findings || findings.length === 0) {
    return (
      <div class="flex flex-col items-center justify-center py-12 text-sm text-neutral-600">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="mb-3 h-10 w-10"><path d="M20 6 9 17l-5-5" /></svg>
        <p>No vulnerabilities found</p>
      </div>
    );
  }
  return (
    <div>
      <div class="overflow-x-auto rounded-lg border border-neutral-800">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-neutral-800 bg-neutral-900">
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Severity</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Scanner</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">URL</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Param</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Confidence</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Payload</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-neutral-800">
            {findings.map(findingRow)}
          </tbody>
        </table>
      </div>
      <div class="mt-2 text-right text-xs text-neutral-500">{findings.length} finding{findings.length !== 1 ? "s" : ""}</div>
    </div>
  );
}

function IntruderResults({ results, total }: { results: any[]; total: number }) {
  if (!results || results.length === 0) {
    return <div class="flex flex-col items-center justify-center py-12 text-sm text-neutral-600">No results</div>;
  }
  return (
    <div>
      <div class="mb-2 text-xs text-neutral-500">{total} total requests · {results.length} results</div>
      <div class="overflow-x-auto rounded-md border border-neutral-800">
        <table class="w-full text-xs">
          <thead>
            <tr class="border-b border-neutral-800 bg-neutral-900">
              <th class="px-2 py-1.5 text-left font-semibold uppercase tracking-wider text-neutral-400">#</th>
              <th class="px-2 py-1.5 text-left font-semibold uppercase tracking-wider text-neutral-400">Payload</th>
              <th class="px-2 py-1.5 text-left font-semibold uppercase tracking-wider text-neutral-400">Status</th>
              <th class="px-2 py-1.5 text-left font-semibold uppercase tracking-wider text-neutral-400">Length</th>
              <th class="px-2 py-1.5 text-left font-semibold uppercase tracking-wider text-neutral-400">Time</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-neutral-800">
            {results.map(intruderResultRow)}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RepeaterResult({ result }: { result: { status_code: number; headers: Record<string, string>; body: string; duration_ms: number; error?: string } }) {
  const bodyPreview = result.body?.slice(0, 500) + (result.body?.length > 500 ? "..." : "");
  return (
    <div class="space-y-2">
      <div class="flex gap-4 text-xs">
        <span class="font-semibold text-neutral-400">Status:</span>
        <span class={result.status_code >= 400 ? "text-danger-500" : "text-success-500"}>{result.status_code}</span>
        <span class="font-semibold text-neutral-400">Time:</span>
        <span class="text-neutral-300">{result.duration_ms?.toFixed(0)}ms</span>
      </div>
      <pre class="max-h-48 overflow-auto rounded border border-neutral-800 bg-neutral-950 p-2 font-mono text-xs text-neutral-300">{bodyPreview}</pre>
    </div>
  );
}

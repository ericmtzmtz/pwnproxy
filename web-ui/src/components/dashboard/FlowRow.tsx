import { useState } from "preact/hooks";
import { FlowDetail } from "./FlowDetail";
import { formatTimeOnly } from "@/utils/formatTimestamp";
import type { FlowRecord } from "@/api/traffic/types";

interface FlowRowProps {
  flow: FlowRecord;
  findingCount: number;
}

const methodColors: Record<string, string> = {
  GET: "text-green-400",
  POST: "text-blue-400",
  PUT: "text-orange-400",
  PATCH: "text-orange-400",
  DELETE: "text-red-400",
  HEAD: "text-neutral-400",
  OPTIONS: "text-neutral-400",
};

const statusColors: Record<string, string> = {
  "2": "text-green-400",
  "3": "text-blue-400",
  "4": "text-yellow-400",
  "5": "text-red-400",
};

function statusColor(code: number | null): string {
  if (!code) return "text-neutral-500";
  const prefix = String(code)[0];
  return statusColors[prefix] ?? "text-neutral-400";
}

function truncateUrl(url: string, max = 60): string {
  if (url.length <= max) return url;
  return url.slice(0, max) + "…";
}

export function FlowRow({ flow, findingCount }: FlowRowProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        onClick={() => setExpanded(!expanded)}
        class="cursor-pointer border-b border-neutral-800 bg-neutral-950 hover:bg-neutral-900/50"
      >
        <td class="px-3 py-2 text-xs text-neutral-500">{flow.id}</td>
        <td class={`px-3 py-2 text-xs font-semibold ${methodColors[flow.method] ?? "text-neutral-300"}`}>
          {flow.method}
        </td>
        <td class="max-w-[400px] truncate px-3 py-2 text-xs text-neutral-300" title={flow.url}>
          {truncateUrl(flow.url)}
        </td>
        <td class={`px-3 py-2 text-xs font-semibold ${statusColor(flow.status_code)}`}>
          {flow.status_code ?? "—"}
        </td>
        <td class="px-3 py-2 text-xs text-neutral-500">
          {formatTimeOnly(flow.timestamp)}
        </td>
        <td class="px-3 py-2 text-xs">
          {findingCount > 0 ? (
            <span class="inline-flex items-center gap-1 rounded-full bg-red-900/40 px-2 py-0.5 text-[11px] font-semibold text-red-400">
              🛡 {findingCount}
            </span>
          ) : (
            <span class="text-neutral-600">—</span>
          )}
        </td>
      </tr>
      {expanded && (
        <tr class="border-b border-neutral-800">
          <td colspan={6} class="bg-neutral-900 px-6 py-4">
            <FlowDetail flowId={flow.id} />
          </td>
        </tr>
      )}
    </>
  );
}

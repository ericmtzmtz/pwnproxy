import { useEffect, useRef } from "preact/hooks";
import { FlowRow } from "./FlowRow";
import type { FlowRecord } from "@/api/traffic/types";

interface FlowTableProps {
  flows: FlowRecord[];
  findingsMap: Record<number, number>;
  onAutoScrolled: () => void;
  onDeleted?: (id: number) => void;
}

export function FlowTable({ flows, findingsMap, onAutoScrolled, onDeleted }: FlowTableProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const prevLengthRef = useRef(flows.length);
  const atTopRef = useRef(true);

  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop } = containerRef.current;
    atTopRef.current = scrollTop < 50;
  };

  useEffect(() => {
    if (flows.length > prevLengthRef.current && atTopRef.current && containerRef.current) {
      containerRef.current.scrollTop = 0;
      onAutoScrolled();
    }
    prevLengthRef.current = flows.length;
  }, [flows.length]);

  if (flows.length === 0) {
    return (
      <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-neutral-800 py-16 text-neutral-600">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="mb-3 h-10 w-10"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        <p class="text-sm">No traffic yet</p>
        <p class="mt-1 text-xs">Route traffic through the proxy to see flows here</p>
      </div>
    );
  }

  return (
    <div class="overflow-x-auto rounded-lg border border-neutral-800">
      <div ref={containerRef} onScroll={handleScroll} class="max-h-[500px] overflow-y-auto">
        <table class="w-full text-sm">
          <thead class="sticky top-0 bg-neutral-900">
            <tr class="border-b border-neutral-800">
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">#</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Method</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">URL</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Status</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Time</th>
              <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Findings</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-neutral-800">
            {flows.map((flow) => (
              <FlowRow key={flow.id} flow={flow} findingCount={findingsMap[flow.id] ?? 0} onDeleted={onDeleted} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

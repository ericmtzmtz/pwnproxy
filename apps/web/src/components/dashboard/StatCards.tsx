interface StatCardsProps {
  flowsCount: number;
  findingsCount: number;
  criticalCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  scannerCount: number;
  scopeCount: number;
  highCount: number;
}

export function StatCards({
  flowsCount,
  findingsCount,
  criticalCount,
  mediumCount,
  infoCount,
  highCount,
  lowCount,
  scannerCount,
  scopeCount,
}: StatCardsProps) {
  return (
    <div class="grid grid-cols-4 gap-4">
      <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-4">
        <p class="text-xs font-semibold uppercase tracking-wider text-neutral-400">Proxy Traffic</p>
        <p class="mt-1 text-2xl font-bold text-neutral-50">{flowsCount}</p>
        <p class="mt-1 text-xs text-neutral-500">flows</p>
      </div>
      <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-4">
        <p class="text-xs font-semibold uppercase tracking-wider text-neutral-400">Findings</p>
        <p class="mt-1 text-2xl font-bold text-neutral-50">{findingsCount}</p>
        <div class="mt-1 flex gap-3 text-xs">
          <span class="text-red-400">{criticalCount} critical</span>
          <span class="text-orange-400">{highCount} high</span>
          <span class="text-yellow-400">{mediumCount} medium</span>
          <span class="text-blue-400">{lowCount} low</span>
          <span class="text-neutral-500">{infoCount} info</span>
        </div>
      </div>
      <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-4">
        <p class="text-xs font-semibold uppercase tracking-wider text-neutral-400">Scanners</p>
        <p class="mt-1 text-2xl font-bold text-neutral-50">{scannerCount}</p>
        <p class="mt-1 text-xs text-neutral-500">active</p>
      </div>
      <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-4">
        <p class="text-xs font-semibold uppercase tracking-wider text-neutral-400">Scope</p>
        <p class="mt-1 text-2xl font-bold text-neutral-50">{scopeCount}</p>
        <p class="mt-1 text-xs text-neutral-500">targets</p>
      </div>
    </div>
  );
}

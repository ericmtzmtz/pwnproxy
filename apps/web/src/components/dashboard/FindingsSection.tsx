import { useEffect, useRef, useState } from "preact/hooks";
import { SeverityFilter } from "./SeverityFilter";
import { FindingsTable } from "./FindingsTable";
import { listFindings } from "@/api/findings/calls";
import type { Finding } from "@/api/findings/types";

interface FindingsSectionProps {
  liveFindings: Finding[];
}

function readParams() {
  if (typeof window === "undefined") return { severity: null, page: 1 };
  const p = new URLSearchParams(location.search);
  return {
    severity: p.get("severity") ?? null,
    page: parseInt(p.get("page") ?? "1", 10) || 1,
  };
}

function writeParams(severity: string | null, page: number) {
  if (typeof window === "undefined") return;
  const p = new URLSearchParams();
  if (severity) p.set("severity", severity);
  if (page > 1) p.set("page", String(page));
  const qs = p.toString();
  const url = qs ? `${location.pathname}?${qs}` : location.pathname;
  history.replaceState(null, "", url);
}

export function FindingsSection({ liveFindings }: FindingsSectionProps) {
  const init = useRef(readParams());
  const [severity, setSeverity] = useState<string | null>(init.current.severity);
  const [page, setPage] = useState(init.current.page);
  const [total, setTotal] = useState(0);
  const [deletedIds, setDeletedIds] = useState<Set<string>>(new Set());
  const perPage = 15;

  const visibleFindings = liveFindings.filter((f) => !deletedIds.has(String(f.id)));
  const filteredFindings = severity
    ? visibleFindings.filter((f) => f.severity === severity)
    : visibleFindings;

  const totalPages = Math.max(1, Math.ceil(total / perPage));

  useEffect(() => {
    setPage(1);
  }, [severity]);

  useEffect(() => {
    writeParams(severity, page);
    listFindings(page, perPage, severity ?? undefined)
      .then((res) => {
        setTotal(res.total);
      })
      .catch(() => {});
  }, [page, severity]);

  const handleDeleted = (id: number) => {
    setDeletedIds((prev) => new Set(prev).add(String(id)));
    setTotal((t) => Math.max(0, t - 1));
  };

  return (
    <div>
      <div class="mb-3 flex items-center justify-between">
        <h2 class="text-sm font-semibold text-neutral-200">Findings</h2>
        <span class="text-xs text-neutral-500">{total} total</span>
      </div>
      <div class="mb-3">
        <SeverityFilter selected={severity} onChange={(s) => setSeverity(s)} />
      </div>
      <FindingsTable findings={filteredFindings} onDeleted={handleDeleted} />
      {total > perPage && (
        <div class="mt-3 flex items-center justify-center gap-2 text-xs text-neutral-500">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            class="rounded px-2 py-1 hover:bg-neutral-800 disabled:opacity-30"
          >
            ◀ Prev
          </button>
          <span class="px-2">
            {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            class="rounded px-2 py-1 hover:bg-neutral-800 disabled:opacity-30"
          >
            Next ▶
          </button>
        </div>
      )}
    </div>
  );
}

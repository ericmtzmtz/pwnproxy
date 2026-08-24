import { useEffect, useState } from "preact/hooks";
import { deleteFinding, triageFeedback } from "@/api/findings/calls";
import { createTab } from "@/api/repeater/calls";
import type { Finding } from "@/api/findings/types";
import { formatTimeOnly } from "@/utils/formatTimestamp";

interface FindingsTableProps {
  findings: Finding[];
  onDeleted?: (id: number) => void;
}

const severityColors: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-neutral-400",
};

const scannerColors: Record<string, string> = {
  sqli: "text-red-300",
  xss: "text-orange-300",
  lfi: "text-yellow-300",
  xxe: "text-purple-300",
  ssrf: "text-cyan-300",
};

function truncateUrl(url: string, max = 50): string {
  if (url.length <= max) return url;
  return url.slice(0, max) + "…";
}

const triageBadge: Record<string, string> = {
  true_positive: "bg-green-900/40 text-green-400",
  false_positive: "bg-neutral-800 text-neutral-500 line-through",
  uncertain: "bg-yellow-900/40 text-yellow-400",
};

function TriageCell({ f }: { f: Finding }) {
  if (!f.triage_verdict) {
    return <span class="text-[11px] text-neutral-600">pending</span>;
  }
  const score = typeof f.triage_score === "number" ? f.triage_score.toFixed(2) : "";
  return (
    <span
      class={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold ${triageBadge[f.triage_verdict] ?? "bg-neutral-800 text-neutral-400"}`}
      title={f.triage_reason ?? ""}
    >
      {f.triage_verdict === "true_positive" ? "TP" : f.triage_verdict === "false_positive" ? "FP" : "?"}
      {score && <span class="font-mono opacity-70">{score}</span>}
    </span>
  );
}

function toast(severity: string, message: string) {
  const title = severity === "error" ? "Error" : "Done";
  window.dispatchEvent(new CustomEvent("pwnproxy-toast", { detail: { title, message, severity } }));
}

export function FindingsTable({ findings, onDeleted }: FindingsTableProps) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [busy, setBusy] = useState<Record<string, boolean>>({});
  const [triageOverride, setTriageOverride] = useState<Record<number, Finding>>({});

  useEffect(() => {
    const handler = (e: Event) => {
      const d = (e as CustomEvent).detail as { finding_id?: number; verdict?: string; method?: string; score?: number | null; reason?: string | null };
      if (!d?.finding_id || !d.verdict) return;
      setTriageOverride((prev) => ({
        ...prev,
        [d.finding_id as number]: {
          ...(prev[d.finding_id as number] ?? findings.find((f) => f.id === d.finding_id)),
          id: d.finding_id as number,
          triage_verdict: d.verdict as Finding["triage_verdict"],
          triage_method: (d.method ?? "heuristic") as Finding["triage_method"],
          triage_score: d.score ?? null,
          triage_reason: d.reason ?? null,
        } as Finding,
      }));
    };
    window.addEventListener("pwnproxy-triage-updated", handler);
    return () => window.removeEventListener("pwnproxy-triage-updated", handler);
  }, [findings]);

  if (findings.length === 0) {
    return (
      <div class="flex flex-col items-center justify-center rounded-lg border border-dashed border-neutral-800 py-12 text-neutral-600">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="mb-3 h-10 w-10"><path d="M20 6 9 17l-5-5"/></svg>
        <p class="text-sm">No findings</p>
      </div>
    );
  }

  return (
    <div class="overflow-x-auto rounded-lg border border-neutral-800" style="min-height:580px">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-neutral-800 bg-neutral-900">
            <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Severity</th>
            <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Method</th>
            <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">URL</th>
            <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Param</th>
            <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Scanner</th>
            <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Triage</th>
            <th class="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-neutral-400">Time</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-neutral-800">
          {findings.map((raw) => {
            const f = triageOverride[raw.id] ?? raw;
            const key = `${f.scanner}-${f.id}`;
            const isOpen = expanded === f.id;
            const isBusy = busy[key];
            return (
              <>
                <tr
                  key={key}
                  onClick={() => setExpanded(isOpen ? null : f.id)}
                  class="cursor-pointer bg-neutral-950 hover:bg-neutral-900/50"
                >
                  <td class={`px-3 py-2 text-xs font-semibold ${severityColors[f.severity] ?? "text-neutral-400"}`}>
                    {f.severity}
                  </td>
                  <td class="px-3 py-2 text-xs text-neutral-400">{f.method || "—"}</td>
                  <td class="max-w-[300px] truncate px-3 py-2 text-xs text-neutral-300" title={f.url}>
                    {truncateUrl(f.url)}
                  </td>
                  <td class="px-3 py-2 font-mono text-xs text-neutral-400">{f.param_name || "—"}</td>
                  <td class={`px-3 py-2 text-xs font-semibold uppercase ${scannerColors[f.scanner] ?? "text-neutral-400"}`}>
                    {f.scanner}
                  </td>
                  <td class="px-3 py-2"><TriageCell f={f} /></td>
                  <td class="px-3 py-2 text-xs text-neutral-500">
                    {formatTimeOnly(f.timestamp)}
                  </td>
                </tr>
                {isOpen && (
                  <tr key={`${key}-detail`} class="bg-neutral-900">
                    <td colspan={7} class="px-6 py-3">
                      <div class="space-y-2">
                        {f.payload && (
                          <div class="text-xs text-neutral-400">
                            <span class="font-semibold text-neutral-300">Payload:</span>{" "}
                            <code class="rounded bg-neutral-800 px-1.5 py-0.5 font-mono text-neutral-200">{f.payload}</code>
                          </div>
                        )}
                        {f.technique && (
                          <div class="text-xs text-neutral-400">
                            <span class="font-semibold text-neutral-300">Technique:</span> {f.technique}
                          </div>
                        )}
                        {f.evidence && (
                          <div class="text-xs text-neutral-400">
                            <span class="font-semibold text-neutral-300">Evidence:</span>{" "}
                            <code class="rounded bg-neutral-800 px-1.5 py-0.5 font-mono text-neutral-200">{f.evidence}</code>
                          </div>
                        )}
                        {f.triage_verdict && (
                          <div class="text-xs text-neutral-400">
                            <span class="font-semibold text-neutral-300">Triage:</span>{" "}
                            <span class={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${triageBadge[f.triage_verdict] ?? ""}`}>{f.triage_verdict}</span>{" "}
                            <span class="font-mono text-neutral-500">{typeof f.triage_score === "number" ? f.triage_score.toFixed(2) : "—"}</span>
                            {f.triage_method && <span class="ml-1 text-neutral-600">via {f.triage_method}</span>}
                            {f.triage_reason && <span class="ml-1 text-neutral-500">· {f.triage_reason}</span>}
                          </div>
                        )}
                        <div class="flex items-center gap-2 pt-1">
                          <button
                            onClick={async (e) => {
                              e.stopPropagation();
                              setBusy((prev) => ({ ...prev, [key]: true }));
                              try {
                                let raw: string;
                                let tabName: string;
                                if (f.request_data?.url) {
                                  // Payload-exact: stored request with the triggering payload
                                  const rd = f.request_data;
                                  const u = new URL(rd.url);
                                  const path = u.pathname + u.search;
                                  const headers = Object.entries(rd.headers || {})
                                    .map(([k, v]) => `${k}: ${v}`)
                                    .join("\n");
                                  const body = rd.body ? `\n\n${rd.body}` : "\n\n";
                                  raw = `${rd.method || "GET"} ${path} HTTP/1.1\n${headers}${body}`;
                                  tabName = `${rd.method || "GET"} ${path.slice(0, 30)}`;
                                } else {
                                  const u = new URL(f.url);
                                  const path = u.pathname + u.search;
                                  const method = f.method || "GET";
                                  let headers = `Host: ${u.host}\nUser-Agent: pwnproxy-repeater/0.1\nAccept: */*`;
                                  if (f.param_location === "header" && f.param_name && f.payload) {
                                    headers = `Host: ${u.host}\n${f.param_name}: ${f.payload}\nAccept: */*`;
                                  }
                                  raw = `${method} ${path} HTTP/1.1\n${headers}\n\n`;
                                  tabName = `${method} ${path.slice(0, 30)}`;
                                }
                                const tab = await createTab({ name: tabName, raw_request: raw });
                                new BroadcastChannel("pwnproxy-repeater").postMessage({ type: "new-tab", focusId: tab.id });
                                window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
                                  detail: { title: "Sent to Repeater", message: `Tab #${tab.id} created`, severity: "success", navTo: "/repeater" },
                                }));
                              } catch {
                                window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
                                  detail: { title: "Error", message: "Failed to create repeater tab", severity: "error" },
                                }));
                              } finally {
                                setBusy((prev) => ({ ...prev, [key]: false }));
                              }
                            }}
                            disabled={isBusy}
                            class="cursor-pointer rounded bg-neutral-800 px-2.5 py-1 text-xs font-medium text-neutral-300 transition-colors hover:bg-neutral-700 disabled:opacity-50"
                          >
                            {isBusy ? "..." : "Send to Repeater"}
                          </button>
                          <button
                            disabled={isBusy}
                            onClick={async (e) => {
                              e.stopPropagation();
                              setBusy((prev) => ({ ...prev, [key]: true }));
                              try {
                                await deleteFinding(f.id);
                                toast("success", `Deleted finding #${f.id}`);
                                onDeleted?.(f.id);
                              } catch (err: any) {
                                toast("error", err.message);
                              } finally {
                                setBusy((prev) => ({ ...prev, [key]: false }));
                              }
                            }}
                            class="cursor-pointer rounded bg-neutral-800 px-2.5 py-1 text-xs font-medium text-neutral-400 transition-colors hover:bg-red-800/40 hover:text-red-400 disabled:opacity-50"
                          >
                            {isBusy ? "..." : "Delete"}
                          </button>
                          <button
                            disabled={isBusy}
                            onClick={async (e) => {
                              e.stopPropagation();
                              setBusy((prev) => ({ ...prev, [key]: true }));
                              try {
                                await triageFeedback(f.id, "true_positive");
                                setTriageOverride((prev) => ({ ...prev, [f.id]: { ...f, triage_verdict: "true_positive", triage_method: "human" } }));
                                toast("success", `Marked #${f.id} as true positive`);
                              } catch (err: any) {
                                toast("error", err.message);
                              } finally {
                                setBusy((prev) => ({ ...prev, [key]: false }));
                              }
                            }}
                            class="cursor-pointer rounded bg-neutral-800 px-2.5 py-1 text-xs font-medium text-green-400 transition-colors hover:bg-green-900/40 disabled:opacity-50"
                          >
                            {isBusy ? "..." : "Mark TP"}
                          </button>
                          <button
                            disabled={isBusy}
                            onClick={async (e) => {
                              e.stopPropagation();
                              setBusy((prev) => ({ ...prev, [key]: true }));
                              try {
                                await triageFeedback(f.id, "false_positive");
                                setTriageOverride((prev) => ({ ...prev, [f.id]: { ...f, triage_verdict: "false_positive", triage_method: "human" } }));
                                toast("success", `Marked #${f.id} as false positive`);
                              } catch (err: any) {
                                toast("error", err.message);
                              } finally {
                                setBusy((prev) => ({ ...prev, [key]: false }));
                              }
                            }}
                            class="cursor-pointer rounded bg-neutral-800 px-2.5 py-1 text-xs font-medium text-yellow-400 transition-colors hover:bg-yellow-800/40 disabled:opacity-50"
                          >
                            {isBusy ? "..." : "Mark FP"}
                          </button>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

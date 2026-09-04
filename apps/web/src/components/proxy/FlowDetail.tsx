import { useEffect, useState } from "preact/hooks";
import { getFlow, deleteFlow, outscopeFlow } from "@/api/traffic/calls";
import { createTab } from "@/api/repeater/calls";
import { buildScanTargetQuery } from "@/utils/scanTarget";
import type { FlowRecord } from "@/api/traffic/types";

interface FlowRequestData {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
}

function buildRawRequest(data: FlowRequestData): string {
  const lines: string[] = [];
  const urlObj = new URL(data.url);
  const path = urlObj.pathname + urlObj.search;
  lines.push(`${data.method} ${path} HTTP/1.1`);
  lines.push(`Host: ${urlObj.host}`);
  
  for (const [key, value] of Object.entries(data.headers)) {
    if (key.toLowerCase() !== "host") {
      lines.push(`${key}: ${value}`);
    }
  }
  
  lines.push("");
  
  if (data.body) {
    lines.push(data.body);
  }
  
  return lines.join("\n");
}

function toast(severity: "success" | "error", message: string) {
  const title = severity === "success" ? "Done" : "Error";
  window.dispatchEvent(new CustomEvent("pwnproxy-toast", { detail: { title, message, severity } }));
}

interface FlowDetailProps {
  flowId: number;
  onDeleted?: (id: number) => void;
  onSendToRepeater?: () => void;
}

function CollapsibleSection({ title, children, defaultOpen = true }: { title: string; children: preact.ComponentChildren; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div class="mb-3">
      <button
        onClick={() => setOpen(!open)}
        class="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-neutral-400 hover:text-neutral-200"
      >
        <span class={`transition-transform ${open ? "rotate-90" : ""}`}>▶</span>
        {title}
      </button>
      {open && <div class="mt-2">{children}</div>}
    </div>
  );
}

function HeadersTable({ headers }: { headers: Record<string, string> | null }) {
  if (!headers || Object.keys(headers).length === 0) {
    return <p class="text-xs text-neutral-500">(empty)</p>;
  }
  return (
    <table class="w-full text-xs">
      <tbody class="divide-y divide-neutral-800">
        {Object.entries(headers).map(([key, val]) => (
          <tr key={key}>
            <td class="w-1/3 truncate py-1 pr-2 font-semibold text-neutral-400">{key}</td>
            <td class="py-1 text-neutral-300 break-all">{val}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function BodyBlock({ body, contentType }: { body: string | null; contentType?: string }) {
  if (!body) return <p class="text-xs text-neutral-500">(empty)</p>;
  const isHtml = contentType?.includes("text/html");
  const isJson = contentType?.includes("application/json") || (!isHtml && body.trim().startsWith("{"));
  return (
    <pre class="max-h-96 overflow-auto rounded bg-neutral-950 p-3 text-xs leading-relaxed"><code class={
      isHtml ? "language-html" : isJson ? "language-json" : ""
    }>{body.length > 10000 ? body.slice(0, 10000) + "\n… (truncated)" : body}</code></pre>
  );
}

export function FlowDetail({ flowId, onDeleted, onSendToRepeater }: FlowDetailProps) {
  const [flow, setFlow] = useState<FlowRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [outscoping, setOutscoping] = useState(false);
  const [sendingToRepeater, setSendingToRepeater] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getFlow(flowId)
      .then((f) => { if (!cancelled) setFlow(f); })
      .catch((e) => { if (!cancelled) setError(e.message); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [flowId]);

  const handleSendToRepeater = async () => {
    if (!flow) return;
    setSendingToRepeater(true);
    try {
      const rawRequest = buildRawRequest({
        method: flow.method,
        url: flow.url,
        headers: flow.request_headers || {},
        body: flow.request_body,
      });
      const tab = await createTab({
        name: `${flow.method} ${new URL(flow.url).pathname.slice(0, 30)}`,
        raw_request: rawRequest,
      });
      new BroadcastChannel("pwnproxy-repeater").postMessage({ type: "new-tab", focusId: tab.id });
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", { detail: { title: "Done", message: `Tab #${tab.id} created — sent to Repeater`, severity: "success", navTo: "/repeater" } }));
      onSendToRepeater?.();
    } catch (err: any) {
      toast("error", err.message || "Failed to send request");
    } finally {
      setSendingToRepeater(false);
    }
  };

  const handleSendToScanner = () => {
    if (!flow) return;
    window.location.href = buildScanTargetQuery({
      method: flow.method,
      url: flow.url,
      headers: flow.request_headers || {},
      body: flow.request_body,
    });
  };

  if (loading) return <p class="text-xs text-neutral-500">Loading…</p>;
  if (error) return <p class="text-xs text-red-400">Error: {error}</p>;
  if (!flow) return null;

  return (
    <div class="space-y-2">
      <div class="flex items-center gap-2 text-xs text-neutral-400">
        <span>{flow.method}</span>
        <span class="text-neutral-600">|</span>
        <span class="font-mono">{flow.url}</span>
        {flow.duration_ms != null && (
          <>
            <span class="text-neutral-600">|</span>
            <span>{flow.duration_ms.toFixed(0)}ms</span>
          </>
        )}
        {flow.tls && (
          <>
            <span class="text-neutral-600">|</span>
            <span class="text-success-500">TLS</span>
          </>
        )}
        {flow.error && (
          <>
            <span class="text-neutral-600">|</span>
            <span class="text-red-400">⚠ {flow.error}</span>
          </>
        )}
        <span class="ml-auto flex gap-2">
          <button
            onClick={async (e: MouseEvent) => {
              e.stopPropagation();
              await handleSendToRepeater();
            }}
            disabled={sendingToRepeater}
            class="rounded bg-neutral-800 px-2 py-0.5 text-[11px] font-medium text-neutral-300 hover:bg-neutral-700 disabled:opacity-50"
          >
            {sendingToRepeater ? "..." : "Repeater"}
          </button>
          <button
            onClick={(e: MouseEvent) => {
              e.stopPropagation();
              handleSendToScanner();
            }}
            class="rounded bg-neutral-800 px-2 py-0.5 text-[11px] font-medium text-neutral-300 hover:bg-neutral-700 disabled:opacity-50"
            title="Send to Scanner"
          >
            Scanner
          </button>
          <button
            onClick={async (e: MouseEvent) => {
              e.stopPropagation();
              setOutscoping(true);
              try {
                await outscopeFlow(flowId);
                toast("success", `Outscoped flow ${flowId}`);
              } catch (err: any) {
                toast("error", err.message);
              } finally {
                setOutscoping(false);
              }
            }}
            disabled={outscoping}
            class="rounded bg-neutral-800 px-2 py-0.5 text-[11px] font-medium text-neutral-300 hover:bg-neutral-700 disabled:opacity-50"
          >
            {outscoping ? "..." : "Outscope"}
          </button>
          <button
            onClick={async (e: MouseEvent) => {
              e.stopPropagation();
              setDeleting(true);
              try {
                await deleteFlow(flowId);
                toast("success", `Deleted flow ${flowId}`);
                onDeleted?.(flowId);
              } catch (err: any) {
                toast("error", err.message);
                setDeleting(false);
              }
            }}
            disabled={deleting}
            class="rounded bg-red-900/40 px-2 py-0.5 text-[11px] font-medium text-red-400 hover:bg-red-800/40 disabled:opacity-50"
          >
            {deleting ? "..." : "Delete"}
          </button>
        </span>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <div>
          <CollapsibleSection title="Request Headers">
            <HeadersTable headers={flow.request_headers} />
          </CollapsibleSection>
          <CollapsibleSection title="Request Body" defaultOpen={!!flow.request_body}>
            <BodyBlock body={flow.request_body} />
          </CollapsibleSection>
        </div>
        <div>
          <CollapsibleSection title="Response Headers">
            <HeadersTable headers={flow.response_headers} />
          </CollapsibleSection>
          <CollapsibleSection title="Response Body" defaultOpen={!!flow.response_body}>
            <BodyBlock
              body={flow.response_body}
              contentType={flow.response_headers?.["content-type"] ?? ""}
            />
          </CollapsibleSection>
        </div>
      </div>
    </div>
  );
}

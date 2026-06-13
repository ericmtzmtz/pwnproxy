import { useEffect, useState } from "preact/hooks";
import { getFlow } from "@/api/traffic/calls";
import type { FlowRecord } from "@/api/traffic/types";

interface FlowDetailProps {
  flowId: number;
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

export function FlowDetail({ flowId }: FlowDetailProps) {
  const [flow, setFlow] = useState<FlowRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

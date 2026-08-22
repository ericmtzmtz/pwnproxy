import { useMemo, useRef } from "preact/hooks";

interface RequestEditorProps {
  value: string;
  onChange: (val: string) => void;
  onSend?: () => void;
  sending?: boolean;
  disabled?: boolean;
}

function highlightHttp(raw: string): string {
  const lines = raw.split("\n");
  return lines
    .map((line) => {
      const esc = line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      // Request line: METHOD path HTTP/1.1
      const reqMatch = esc.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+(HTTP\/[\d.]+)$/i);
      if (reqMatch) {
        const [_, method, path, version] = reqMatch;
        return `<span class="text-pink-400 font-bold">${method}</span> <span class="text-sky-300">${path}</span> <span class="text-neutral-500">${version}</span>`;
      }
      // Header line: Name: value
      const headerMatch = esc.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
      if (headerMatch && !line.startsWith(" ")) {
        return `<span class="text-purple-300">${headerMatch[1]}</span>: <span class="text-neutral-300">${headerMatch[2]}</span>`;
      }
      // Body (after blank line)
      if (line === "") return "&nbsp;";
      return esc;
    })
    .join("\n");
}

export function RequestEditor({ value, onChange, onSend, sending, disabled }: RequestEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const lineCount = useMemo(() => value.split("\n").length, [value]);

  const handleKeyDown = (e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      onSend?.();
    }
  };

  // Sync scroll between gutter and textarea
  const handleScroll = (e: Event) => {
    const ta = e.target as HTMLTextAreaElement;
    const gutter = document.getElementById("req-gutter");
    if (gutter) gutter.scrollTop = ta.scrollTop;
  };

  return (
    <div class="flex h-full flex-col">
      {/* Toolbar */}
      <div class="flex items-center gap-1 border-b border-neutral-800 px-2 py-1">
        <button
          onClick={onSend}
          disabled={disabled || sending}
          class="inline-flex items-center gap-1.5 rounded bg-primary-600 px-3 py-1 text-[11px] font-semibold text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800"
        >
          {sending ? "Sending…" : "▶ Send"}
        </button>
        <span class="ml-1 hidden text-[10px] text-neutral-600 sm:inline">Ctrl+Enter</span>
        <div class="ml-auto flex items-center gap-0.5">
          <button
            onClick={() => onChange(encodeURIComponent(value))}
            title="URL Encode"
            class="rounded px-1.5 py-0.5 text-[10px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
          >
            URL Encode
          </button>
          <button
            onClick={() => {
              try { onChange(decodeURIComponent(value)); } catch { /* keep as-is */ }
            }}
            title="URL Decode"
            class="rounded px-1.5 py-0.5 text-[10px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
          >
            URL Decode
          </button>
          <button
            onClick={() => { try { onChange(btoa(value)); } catch { /* non-latin1 */ } }}
            title="Base64 Encode"
            class="rounded px-1.5 py-0.5 text-[10px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
          >
            B64 Encode
          </button>
          <button
            onClick={() => { try { onChange(atob(value)); } catch { /* invalid */ } }}
            title="Base64 Decode"
            class="rounded px-1.5 py-0.5 text-[10px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
          >
            B64 Decode
          </button>
          <span class="mx-1 h-3 w-px bg-neutral-800" />
          <button
            onClick={() => navigator.clipboard?.writeText(value)}
            title="Copy"
            class="rounded px-1.5 py-0.5 text-[10px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
          >
            Copy
          </button>
          <button
            onClick={() => onChange("")}
            title="Clear"
            class="rounded px-1.5 py-0.5 text-[10px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
          >
            Clear
          </button>
          <button
            onClick={() => onChange(copyAsCurl(value))}
            title="Copy as cURL"
            class="rounded px-1.5 py-0.5 text-[10px] text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-300"
          >
            cURL
          </button>
        </div>
      </div>

      {/* Editor: gutter + textarea */}
      <div class="flex min-h-0 flex-1">
        <div
          id="req-gutter"
          class="w-10 shrink-0 overflow-hidden border-r border-neutral-800 bg-neutral-950 py-2 text-right font-mono text-[11px] leading-[1.4] text-neutral-700 select-none"
        >
          {Array.from({ length: lineCount }, (_, i) => (
            <div key={i} class="pr-2">{i + 1}</div>
          ))}
        </div>
        <textarea
          ref={textareaRef}
          value={value}
          onInput={(e) => onChange((e.target as HTMLTextAreaElement).value)}
          onScroll={handleScroll}
          onKeyDown={handleKeyDown}
          spellcheck={false}
          class="w-full flex-1 resize-none border-0 bg-transparent px-3 py-2 font-mono text-[11px] leading-[1.4] text-neutral-100 outline-none placeholder-neutral-600"
          placeholder="GET / HTTP/1.1&#10;Host: example.com&#10;"
        />
      </div>
    </div>
  );
}

function copyAsCurl(raw: string): string {
  // Best-effort raw_request -> curl command. Not perfect, but useful.
  const lines = raw.split("\n");
  if (!lines[0]) return raw;
  const [method, path] = lines[0].split(" ");
  const headers: string[] = [];
  const bodyLines: string[] = [];
  let inBody = false;
  for (const l of lines.slice(1)) {
    if (!inBody && l === "") { inBody = true; continue; }
    if (!inBody && l.includes(":")) headers.push(l);
    else if (inBody) bodyLines.push(l);
  }
  const url = path?.startsWith("http") ? path : `http://__HOST__${path ?? ""}`;
  const parts = [`curl -X ${method ?? "GET"} '${url}'`];
  for (const h of headers) parts.push(`  -H '${h.replace(/'/g, "\\'")}'`);
  if (bodyLines.length) parts.push(`  -d '${bodyLines.join("\\n").replace(/'/g, "\\'")}'`);
  return parts.join(" \\\n");
}

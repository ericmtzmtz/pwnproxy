import { useEffect, useMemo, useRef, useState } from "preact/hooks";

export interface PaletteCommand {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

interface CommandPaletteProps {
  commands: PaletteCommand[];
  onClose: () => void;
}

export function CommandPalette({ commands, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(
      (c) => c.label.toLowerCase().includes(q) || (c.hint ?? "").toLowerCase().includes(q),
    );
  }, [commands, query]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    setSelected(0);
  }, [query]);

  const run = (cmd: PaletteCommand) => {
    cmd.run();
    onClose();
  };

  return (
    <div
      class="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[15vh]"
      onClick={onClose}
    >
      <div
        class="w-full max-w-md overflow-hidden rounded-lg border border-neutral-700 bg-neutral-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div class="flex items-center gap-2 border-b border-neutral-800 px-3 py-2.5">
          <svg class="h-4 w-4 text-neutral-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input
            ref={inputRef}
            value={query}
            onInput={(e) => setQuery((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setSelected((s) => Math.min(s + 1, filtered.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setSelected((s) => Math.max(s - 1, 0)); }
              else if (e.key === "Enter") { e.preventDefault(); if (filtered[selected]) run(filtered[selected]); }
              else if (e.key === "Escape") { onClose(); }
            }}
            placeholder="Search commands…"
            class="w-full bg-transparent text-sm text-neutral-100 outline-none placeholder:text-neutral-600"
          />
        </div>
        <div class="max-h-80 overflow-y-auto py-1">
          {filtered.length === 0 ? (
            <div class="px-4 py-6 text-center text-xs text-neutral-600">No commands match "{query}"</div>
          ) : (
            filtered.map((cmd, i) => (
              <button
                key={cmd.id}
                onClick={() => run(cmd)}
                onMouseEnter={() => setSelected(i)}
                class={`flex w-full items-center justify-between px-4 py-2 text-left text-sm transition-colors ${
                  i === selected ? "bg-primary-900/40 text-primary-200" : "text-neutral-300"
                }`}
              >
                <span>{cmd.label}</span>
                {cmd.hint && <span class="text-[10px] text-neutral-600">{cmd.hint}</span>}
              </button>
            ))
          )}
        </div>
        <div class="flex items-center gap-3 border-t border-neutral-800 px-4 py-1.5 text-[10px] text-neutral-600">
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  );
}

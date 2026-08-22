import { useState } from "preact/hooks";
import { togglePlugin } from "@/api/plugins/calls";

interface PluginToggleProps {
  name: string;
  disabled: boolean;
  onToggle?: (name: string, newDisabled: boolean) => void;
}

export function PluginToggle({ name, disabled, onToggle }: PluginToggleProps) {
  const [loading, setLoading] = useState(false);

  async function handleClick() {
    setLoading(true);
    try {
      await togglePlugin(name);
      onToggle?.(name, !disabled);
    } catch {
      window.dispatchEvent(new CustomEvent("pwnproxy-toast", {
        detail: { title: "Toggle failed", message: `Could not toggle ${name}`, severity: "error" },
      }));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div class="rounded-lg border p-3 transition-colors border-neutral-800 bg-neutral-950">
      <div class="flex items-center justify-between">
        <span class="text-xs font-semibold uppercase tracking-wider text-neutral-400">{name}</span>
        <span class={`inline-flex h-2 w-2 rounded-full ${disabled ? "bg-neutral-700" : "bg-success-500"}`} title={disabled ? "Disabled" : "Active"} />
      </div>
      <p class="mt-1 text-[11px] text-neutral-500">{disabled ? "Disabled" : "Ready"}</p>
      <button
        onClick={handleClick}
        disabled={loading}
        type="button"
        role="switch"
        aria-checked={!disabled}
        class={`relative mt-2 inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 focus:ring-offset-neutral-950 ${
          !disabled ? "bg-primary-600" : "bg-neutral-700"
        }`}
      >
        <span class={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition duration-200 ease-in-out ${
          !disabled ? "translate-x-4" : "translate-x-0.5"
        }`} />
      </button>
    </div>
  );
}

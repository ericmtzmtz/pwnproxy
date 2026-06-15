import { useEffect, useRef, useState } from "preact/hooks";

export interface ToastData {
  id: string;
  icon: string;
  title: string;
  message: string;
  navTo: string;
  severity: string;
}

interface ToastProps {
  toast: ToastData;
  onDismiss: (id: string) => void;
  duration?: number;
}

export function Toast({ toast, onDismiss, duration = 4000 }: ToastProps) {
  const [exiting, setExiting] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hoverRef = useRef(false);

  const startTimer = () => {
    if (hoverRef.current) return;
    timerRef.current = setTimeout(() => {
      setExiting(true);
      setTimeout(() => onDismiss(toast.id), 300);
    }, duration);
  };

  const clearTimer = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
  };

  useEffect(() => {
    startTimer();
    return clearTimer;
  }, []);

const borderColor = {
      error: "border-l-red-500",
      warning: "border-l-orange-500",
      success: "border-l-green-500",
      info: "border-l-blue-500",
    }[toast.severity] ?? "border-l-neutral-500";

  return (
    <div
      role="alert"
      data-exiting={exiting}
      onClick={() => { clearTimer(); window.location.href = toast.navTo; }}
      onMouseEnter={() => { hoverRef.current = true; }}
      onMouseLeave={() => { hoverRef.current = false; startTimer(); }}
      class={`flex cursor-pointer items-start gap-3 rounded-lg border border-neutral-800 bg-neutral-900 p-3 shadow-lg transition-all duration-300 hover:bg-neutral-800 ${borderColor} border-l-4 ${
        exiting ? "translate-x-full opacity-0" : "translate-x-0 opacity-100"
      }`}
    >
      <span class="mt-0.5 text-lg">{toast.icon}</span>
      <div class="min-w-0 flex-1">
        <p class="text-sm font-semibold text-neutral-100">{toast.title}</p>
        <p class="mt-0.5 truncate text-xs text-neutral-400">{toast.message}</p>
      </div>
      <button
        onClick={(e) => { e.stopPropagation(); onDismiss(toast.id); }}
        class="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-neutral-500 hover:bg-neutral-700 hover:text-neutral-300"
      >
        ✕
      </button>
    </div>
  );
}

import { useCallback, useEffect, useState } from "preact/hooks";
import { useWebSocket } from "@/hooks/useWebSocket";
import { getPreset, resolveIcon } from "./TOAST_PRESETS";
import { ToastContainer } from "./ToastContainer";
import type { ToastData } from "./Toast";

const WS_HOST = import.meta.env.PUBLIC_API_BASE
  ? new URL(import.meta.env.PUBLIC_API_BASE).host
  : "127.0.0.1:8000";

function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function NotificationLayer() {
  const [toasts, setToasts] = useState<ToastData[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback((t: ToastData) => {
    setToasts((prev) => [t, ...prev].slice(0, 3));
  }, []);

  useEffect(() => {
    const handler = (e: CustomEvent<Partial<ToastData>>) => {
      const d = e.detail;
      if (!d.title || !d.message) return;
      addToast({
        id: d.id ?? generateId(),
        icon: d.icon ?? "ℹ️",
        title: d.title,
        message: d.message,
        navTo: d.navTo ?? "/",
        severity: d.severity ?? "info",
      });
    };
    window.addEventListener("pwnproxy-toast", handler as EventListener);
    return () => window.removeEventListener("pwnproxy-toast", handler as EventListener);
  }, [addToast]);

  const onWsMessage = useCallback(
    (msg: { type: string; [key: string]: unknown }) => {
      if (msg.type === "triage.updated") {
        window.dispatchEvent(new CustomEvent("pwnproxy-triage-updated", { detail: msg }));
        return;
      }
      if (msg.type === "crawler.url") {
        window.dispatchEvent(new CustomEvent("pwnproxy-crawler-url", { detail: msg }));
        return;
      }
      if (msg.type === "crawl.completed") {
        const stats = (msg as any).stats ?? msg;
        addToast({
          id: generateId(),
          icon: "✅",
          title: "Crawl completed",
          message: `Fetched: ${msg.fetched ?? "?"}, Discovered: ${msg.discovered ?? "?"}`,
          navTo: "/crawler",
          severity: "success",
        });
        return;
      }
      if (msg.type === "crawl.failed") {
        addToast({
          id: generateId(),
          icon: "❌",
          title: "Crawl failed",
          message: (msg.error as string) ?? "Unknown error",
          navTo: "/crawler",
          severity: "error",
        });
        return;
      }
      if (msg.type === "bruteforce.completed") {
        addToast({
          id: generateId(),
          icon: "🔓",
          title: "Bruteforce completed",
          message: `Hits: ${msg.found ?? "?"}, Probed: ${msg.probed ?? "?"}`,
          navTo: "/bruteforce",
          severity: "success",
        });
        return;
      }
      if (msg.type === "bruteforce.failed") {
        addToast({
          id: generateId(),
          icon: "❌",
          title: "Bruteforce failed",
          message: (msg.error as string) ?? "Unknown error",
          navTo: "/bruteforce",
          severity: "error",
        });
        return;
      }
      const preset = getPreset(msg.type as string);
      if (!preset) return;

      if (preset.badgeTarget) {
        const badge = document.querySelector(preset.badgeTarget);
        if (badge) {
          const current = parseInt(badge.textContent ?? "0", 10);
          badge.textContent = `${current + 1}`;
          badge.classList.remove("hidden");
        }
      }

      if (preset.shouldToast(msg as never)) {
        const isFlow = msg.type === "flow";
        let title: string;
        if (isFlow) {
          const u = new URL(msg.url as string);
          title = `${msg.method as string} ${u.hostname}`;
        } else {
          title = `${(msg.scanner ?? msg.type) as string} — ${msg.severity as string}`;
        }
        addToast({
          id: generateId(),
          icon: resolveIcon(preset, msg as never),
          title,
          message: msg.url as string,
          navTo: preset.navTo,
          severity: (isFlow ? "info" : (msg.severity as string)) ?? "info",
        });
      }
    },
    [addToast],
  );

  useWebSocket({
    url: `ws://${WS_HOST}/ws/events`,
    onMessage: onWsMessage,
  });

  return <ToastContainer toasts={toasts} onDismiss={dismissToast} />;
}

import type { WsMessage } from "@/hooks/useWebSocket";

export interface ToastPreset {
  shouldToast: (msg: WsMessage) => boolean;
  icon: string | ((msg: WsMessage) => string);
  navTo: string;
  badgeTarget: string | null;
}

export const TOAST_PRESETS: Record<string, ToastPreset> = {
  finding: {
    shouldToast: (m) => m.severity === "critical" || m.severity === "high",
    icon: (m) => (m.severity === "critical" ? "🔴" : "🟡"),
    navTo: "/",
    badgeTarget: null,
  },
  flow: {
    shouldToast: () => true,
    icon: "🔄",
    navTo: "/",
    badgeTarget: null,
  },
  interceptor: {
    shouldToast: () => true,
    icon: "✋",
    navTo: "/interceptor",
    badgeTarget: "#sidebar-interceptor-badge",
  },
  scan_status: {
    shouldToast: (m) => m.status === "completed" || m.status === "error",
    icon: (m) => (m.status === "error" ? "❌" : "✅"),
    navTo: "/scanners",
    badgeTarget: "#sidebar-scanners-badge",
  },
  bruteforce: {
    shouldToast: () => false,
    icon: "🔓",
    navTo: "/bruteforce",
    badgeTarget: null,
  },
};

export function getPreset(type: string): ToastPreset | undefined {
  return TOAST_PRESETS[type];
}

export function resolveIcon(preset: ToastPreset, msg: WsMessage): string {
  return typeof preset.icon === "function" ? preset.icon(msg) : preset.icon;
}

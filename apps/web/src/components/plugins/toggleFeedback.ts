import { PluginToggleError, togglePlugin } from "@/api/plugins/calls";
import type { ToggleResponse } from "@/api/plugins/types";

/**
 * Toggle a plugin and report the outcome through the app's NotificationLayer.
 *
 * Both plugin surfaces (Settings and Scanners) share this so they behave the
 * same: the server is the only one that decides the new state, and on `404`,
 * `409` or `500` the toast carries the server's `detail` and the caller reloads
 * the catalog — no optimistic state is kept anywhere.
 */

type ToastSeverity = "info" | "success" | "error";

interface ToastDetail {
  title: string;
  message: string;
  severity: ToastSeverity;
}

function toast(detail: ToastDetail): void {
  window.dispatchEvent(new CustomEvent("pwnproxy-toast", { detail }));
}

const FAILURE_TITLES: Record<number, string> = {
  404: "Plugin not in the catalog",
  409: "Plugin cannot be turned on",
  500: "Could not save the plugin state",
  503: "Plugin loader not available",
};

/** Returns the server's answer, or `null` when the toggle failed (already toasted). */
export async function togglePluginWithFeedback(name: string): Promise<ToggleResponse | null> {
  try {
    const result = await togglePlugin(name);
    const enabled = result.status === "enabled";
    toast({
      title: `${name} ${enabled ? "enabled" : "disabled"}`,
      message: enabled ? "New traffic will be scanned by this plugin." : "This plugin stops scanning new traffic.",
      severity: "success",
    });
    return result;
  } catch (error) {
    if (error instanceof PluginToggleError) {
      toast({
        title: FAILURE_TITLES[error.status] ?? "Could not change the plugin state",
        message: error.message,
        severity: "error",
      });
    } else {
      toast({
        title: "Could not change the plugin state",
        message: error instanceof Error ? error.message : String(error),
        severity: "error",
      });
    }
    return null;
  }
}

import { API_BASE } from "@/core";
import { apiFetch } from "@/api/client";
import type {
  CollectionItem,
  CollectionResponse,
  PluginActionResponse,
  PluginSchema,
  PluginSettingsResponse,
} from "./types";

/**
 * Failure of any plugin configuration route, carrying the HTTP status and —when
 * the server sent one— the field a `422` names.
 *
 * The `detail` is the server's own text (HTTP code, message, and for a `422`
 * `{field, message}`); the UI shows it as-is because every rule lives there:
 * `404` unknown plugin/collection/action, `403` scope, `409` broken plugin, full
 * collection or an action on a plugin that is not loaded, `422` validation,
 * `500` fixed body.
 */
export class PluginConfigError extends Error {
  readonly status: number;
  /** Field named by a `422` (`webhooks.signing_key` for a collection item). */
  readonly field: string | null;

  constructor(status: number, message: string, field: string | null = null) {
    super(message);
    this.name = "PluginConfigError";
    this.status = status;
    this.field = field;
  }
}

/** Detail the server sends: a string, or `{field, message}` for a `422`. */
function parseDetail(body: unknown): { message: string; field: string | null } {
  if (typeof body === "object" && body !== null) {
    const detail = (body as Record<string, unknown>)["detail"];
    if (typeof detail === "string" && detail.length > 0) {
      return { message: detail, field: null };
    }
    if (typeof detail === "object" && detail !== null) {
      const record = detail as Record<string, unknown>;
      const message = record["message"];
      const field = record["field"];
      return {
        message: typeof message === "string" && message.length > 0 ? message : "Invalid value",
        field: typeof field === "string" && field.length > 0 ? field : null,
      };
    }
  }
  return { message: "", field: null };
}

/** Path of a plugin resource; every segment is escaped. */
function pluginPath(name: string, suffix = ""): string {
  return `${API_BASE}/plugins/${encodeURIComponent(name)}${suffix}`;
}

async function failure(res: Response): Promise<PluginConfigError> {
  const body: unknown = await res.json().catch(() => null);
  const detail = parseDetail(body);
  const fallback = res.statusText.length > 0 ? res.statusText : `HTTP ${res.status}`;
  return new PluginConfigError(res.status, detail.message || fallback, detail.field);
}

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(url, init);
  if (!res.ok) throw await failure(res);
  return res.json() as Promise<T>;
}

/** Ask the plugin (through the server) what it declares. Empty = no configuration. */
export function getPluginSchema(name: string): Promise<PluginSchema> {
  return call<PluginSchema>(pluginPath(name, "/schema"));
}

/** Read the settings; a secret comes back as `{"set": …}`, never as a value. */
export function getPluginSettings(name: string): Promise<PluginSettingsResponse> {
  return call<PluginSettingsResponse>(pluginPath(name, "/settings"));
}

/** Write **only** the keys sent: an absent key is not touched. */
export function patchPluginSettings(
  name: string,
  values: Record<string, unknown>,
): Promise<PluginSettingsResponse> {
  return call<PluginSettingsResponse>(pluginPath(name, "/settings"), {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ values }),
  });
}

/** One collection with its items and its capacity. */
export function listCollectionItems(name: string, collection: string): Promise<CollectionResponse> {
  return call<CollectionResponse>(
    pluginPath(name, `/collections/${encodeURIComponent(collection)}`),
  );
}

export function createCollectionItem(
  name: string,
  collection: string,
  values: Record<string, unknown>,
): Promise<CollectionItem> {
  return call<CollectionItem>(pluginPath(name, `/collections/${encodeURIComponent(collection)}`), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ values }),
  });
}

export function updateCollectionItem(
  name: string,
  collection: string,
  itemId: string,
  values: Record<string, unknown>,
): Promise<CollectionItem> {
  return call<CollectionItem>(
    pluginPath(name, `/collections/${encodeURIComponent(collection)}/${encodeURIComponent(itemId)}`),
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ values }),
    },
  );
}

/** `204`: no body to read, so the caller reloads the collection. */
export async function deleteCollectionItem(
  name: string,
  collection: string,
  itemId: string,
): Promise<void> {
  const res = await apiFetch(
    pluginPath(name, `/collections/${encodeURIComponent(collection)}/${encodeURIComponent(itemId)}`),
    { method: "DELETE" },
  );
  if (!res.ok) throw await failure(res);
}

/** Run an action: `200` completed inline, `202` running with a `task_id`. */
export function runPluginAction(
  name: string,
  action: string,
  parameters: Record<string, unknown>,
): Promise<PluginActionResponse> {
  return call<PluginActionResponse>(pluginPath(name, `/actions/${encodeURIComponent(action)}`), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ parameters }),
  });
}

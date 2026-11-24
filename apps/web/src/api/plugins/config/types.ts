/**
 * Types for the plugin configuration contract
 * (`pwnproxy/transport/rest/plugin_config.py`).
 *
 * Everything here is what the **server** publishes: the schema a plugin
 * declares (`GET …/schema`), the rendered values of a read (`{"value": …}` /
 * `{"set": bool}`), the items of a collection and the outcome of an action. The
 * UI never recomputes any of it — not the secret-ness of a field, not the
 * capacity of a collection, not the outcome of a write.
 *
 * Secrets never travel: a read answers `{"set": true|false}` for a field the
 * schema marks `secret`, and there is no route that returns the value. So a
 * `RenderedValue` with `set` is all a client will ever see of one.
 */

/** Closed vocabulary of a declared field (`schema_version: 1`). */
export type FieldType = "string" | "integer" | "number" | "boolean" | "enum" | "array";

/** Token scope an action needs. Undeclared means `full` (the server decides). */
export type ActionScope = "agent" | "full";

/** One declarable value: a setting, a collection item field or a parameter. */
export interface FieldSpec {
  key: string;
  type: FieldType;
  /** Always present: a client should not tell `absent` from `false`. */
  required: boolean;
  /** Write-only. Read as `{"set": …}`; needs a `full` token to be written. */
  secret: boolean;
  /** The plugin owns the value; the server rejects a write with `422`. */
  read_only: boolean;
  help?: string;
  /** Value the plugin reports when it has none (never set on a `secret`). */
  default?: unknown;
  choices?: string[];
  minimum?: number;
  maximum?: number;
  max_length?: number;
  max_items?: number;
  items?: string;
}

/** A list of items the plugin owns, with its capacity (`max_items`). */
export interface CollectionSpec {
  name: string;
  max_items: number;
  help?: string;
  item: FieldSpec[];
}

/** An operation the plugin can run on demand. */
export interface ActionSpec {
  name: string;
  long_running: boolean;
  requires_scope: ActionScope;
  help?: string;
  /** Never `secret` and never `read_only`: the schema is rejected server-side. */
  parameters: FieldSpec[];
}

/** What a plugin declares: `GET /api/v1/plugins/{name}/schema`. */
export interface PluginSchema {
  plugin: string;
  schema_version: number;
  settings: FieldSpec[];
  collections: CollectionSpec[];
  actions: ActionSpec[];
}

/** A normal value. */
export interface RenderedValueWithValue {
  value: unknown;
}

/** A secret: whether the plugin reports it as configured. Never the value. */
export interface RenderedValueWithSet {
  set: boolean;
}

export type RenderedValue = RenderedValueWithValue | RenderedValueWithSet;

/** `GET|PATCH /api/v1/plugins/{name}/settings`. */
export interface PluginSettingsResponse {
  plugin: string;
  schema_version: number;
  values: Record<string, RenderedValue>;
}

/** One element of a collection. `id` is what edit and delete address. */
export interface CollectionItem {
  id: string;
  values: Record<string, RenderedValue>;
}

/** `GET /api/v1/plugins/{name}/collections/{collection}`. */
export interface CollectionResponse {
  plugin: string;
  collection: string;
  schema_version: number;
  max_items: number;
  items: CollectionItem[];
}

/** `POST /api/v1/plugins/{name}/actions/{action}`: inline or via the task store. */
export interface PluginActionResponse {
  plugin: string;
  action: string;
  status: string;
  /** Present when the server answered `202`: the result lands in `GET /tasks/{id}`. */
  task_id?: string;
  result?: unknown;
}

/** The `422` body: which field broke a rule and the rule, as the server wrote it. */
export interface PluginConfigErrorDetail {
  field: string;
  message: string;
}

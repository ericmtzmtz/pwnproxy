import type { FieldSpec, RenderedValue } from "@/api/plugins/config/types";

/**
 * Presentation helpers for the generated plugin forms.
 *
 * The schema carries a machine `key` and an optional `help`, and no human
 * label, so the visible label is derived from the key (never a hardcoded name:
 * the UI does not know any plugin or any of its fields).
 */

/** `signing_key` → `Signing key`. */
export function humanize(key: string): string {
  if (key.length === 0) return "";
  const words = key.replace(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** The visible label of a declared field. */
export function labelFor(spec: FieldSpec): string {
  return humanize(spec.key);
}

/** `true` when a rendered value is the `{"set": bool}` form (a secret). */
export function isSecretState(rendered: RenderedValue | undefined): boolean {
  return rendered !== undefined && typeof rendered === "object" && rendered !== null && "set" in rendered;
}

/** The value of a plain field, or `undefined` (absent, or a secret). */
export function rawValue(rendered: RenderedValue | undefined): unknown {
  if (rendered === undefined || rendered === null) return undefined;
  if (isSecretState(rendered)) return undefined;
  return (rendered as { value: unknown }).value;
}

/** Whether the plugin reports a secret as configured (`{"set": true}`). */
export function secretIsSet(rendered: RenderedValue | undefined): boolean {
  if (!isSecretState(rendered)) return false;
  return (rendered as { set: boolean }).set === true;
}

/** Inert text for a rendered value: read-only rows, placeholders, summaries. */
export function formatValue(rendered: RenderedValue | undefined): string {
  if (rendered === undefined || rendered === null) return "—";
  if (isSecretState(rendered)) return secretIsSet(rendered) ? "Configured" : "Not configured";
  const value = rawValue(rendered);
  if (value === undefined || value === null || value === "") return "—";
  if (Array.isArray(value)) return value.length === 0 ? "—" : value.join(", ");
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Value a form starts with when the plugin did not report the key. */
export function initialValue(spec: FieldSpec, rendered: RenderedValue | undefined): unknown {
  const value = rawValue(rendered);
  if (value !== undefined) return value;
  if (spec.type === "boolean") return false;
  if (spec.type === "array") return [];
  if (spec.default !== undefined && !spec.secret) return spec.default;
  return "";
}

/** The field a `422` names, without the collection prefix (`webhooks.signing_key`). */
export function bareField(field: string | null): string | null {
  if (!field) return null;
  const parts = field.split(".");
  return parts[parts.length - 1] || null;
}


import type { FieldSpec, RenderedValue } from "@/api/plugins/config/types";
import { formatValue, initialValue, labelFor, rawValue, secretIsSet } from "./format";

/**
 * One field of a generated form, painted from its `FieldSpec`.
 *
 * The component knows the closed vocabulary of the contract and nothing else:
 * no key is named here, so a new plugin (or a new field of an existing one)
 * appears without touching this file. Two rules it must never break:
 *
 * - A `secret` is **write-only**: the input starts empty, its placeholder says
 *   whether the plugin reports it as configured, and no value is ever bound to
 *   it. Only what the user types is sent (`PATCH` of the changed keys).
 * - A `read_only` field is text, not an input: the plugin owns it and the server
 *   answers `422` for any write.
 * - An `immutable` field is a normal input while the item is being created and a
 *   muted, non-editable one once it exists (`locked`): the server refuses it in a
 *   `PATCH`, so the edit form does not send it.
 */

export interface SchemaFieldProps {
  spec: FieldSpec;
  /** Server-rendered current value (`{"value"}` or, for a secret, `{"set"}`). */
  value: RenderedValue | undefined;
  /** What the user has typed for this key; `undefined` means "untouched". */
  draft: unknown;
  disabled?: boolean;
  /** Shown next to the control when it is disabled on purpose (e.g. `agent`). */
  disabledReason?: string;
  /**
   * `true` when the value can no longer change: an `immutable` field of an item
   * that already exists (written on the create, refused by the server in a
   * `PATCH`). The create form passes `false`, so the same field is a normal input
   * there.
   */
  locked?: boolean;
  error?: string | null;
  /** Prefix for the generated ids (`useId()` of the owning form). */
  idPrefix: string;
  onChange: (value: unknown) => void;
}

const INPUT_CLASS =
  "w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-1.5 text-sm text-neutral-100 placeholder-neutral-500 transition-colors focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 disabled:cursor-not-allowed disabled:opacity-60";
const LABEL_CLASS = "block text-xs font-medium text-neutral-400";
const HELP_CLASS = "mt-1 text-[11px] text-neutral-500";
const ERROR_CLASS = "mt-1 text-[11px] font-medium text-danger-400";

function asList(value: unknown): string[] {
  return Array.isArray(value) ? value.map((item) => String(item)) : [];
}

export function SchemaField({
  spec,
  value,
  draft,
  disabled = false,
  disabledReason,
  locked = false,
  error,
  idPrefix,
  onChange,
}: SchemaFieldProps) {
  const inputId = `${idPrefix}-${spec.key}`;
  const helpId = spec.help ? `${inputId}-help` : undefined;
  const errorId = error ? `${inputId}-error` : undefined;
  const describedBy = [helpId, errorId].filter(Boolean).join(" ") || undefined;
  const label = labelFor(spec);

  const help = spec.help ? (
    <p id={helpId} class={HELP_CLASS}>
      {spec.help}
    </p>
  ) : null;
  const failure = error ? (
    // Not a live region: the message is announced through the focus that the form
    // moves to the field a `422` names, and `aria-describedby` lists it only while
    // it is shown (referenced text is read out even when hidden).
    <p id={errorId} class={ERROR_CLASS}>
      {error}
    </p>
  ) : null;

  if (spec.read_only) {
    return (
      <div>
        <span class={LABEL_CLASS}>{label}</span>
        <p class="mt-1 text-sm text-neutral-200">{formatValue(value)}</p>
        <p class={HELP_CLASS}>Read-only — the plugin owns this value.</p>
        {help}
      </div>
    );
  }

  if (locked) {
    // Immutable on an existing item: it was written on the create and the server
    // refuses it in a `PATCH` (`422` `cannot change after the item is created`),
    // so the field is not part of the payload either.
    //
    // `readOnly` + `aria-disabled`, not `disabled`: `disabled` removes the
    // control from the tab order entirely, so keyboard and screen-reader users
    // could never land on it and the value (an item's `name`, a URL) is exactly
    // what they may need to copy. The muted styling carries the same signal
    // visually and the hint travels through `aria-describedby`.
    const hintId = `${inputId}-immutable`;
    return (
      <div>
        <label for={inputId} class={LABEL_CLASS}>
          {label}
        </label>
        <input
          id={inputId}
          type="text"
          value={formatValue(value)}
          readOnly
          aria-disabled="true"
          aria-describedby={[hintId, helpId].filter(Boolean).join(" ")}
          class={`mt-1 ${INPUT_CLASS} cursor-not-allowed border-neutral-800 bg-neutral-900 text-neutral-400`}
        />
        <p id={hintId} class={HELP_CLASS}>
          Set when the item is created.
        </p>
        {help}
      </div>
    );
  }

  if (spec.secret) {
    const configured = secretIsSet(value);
    return (
      <div>
        <div class="flex flex-wrap items-baseline justify-between gap-2">
          <label for={inputId} class={LABEL_CLASS}>
            {label}
            {spec.required ? <span class="ml-1 text-neutral-500">(required)</span> : null}
          </label>
          <span
            class={`text-[11px] font-medium ${configured ? "text-success-500" : "text-neutral-500"}`}
          >
            {configured ? "Configured" : "Not configured"}
          </span>
        </div>
        <input
          id={inputId}
          type="password"
          autocomplete="new-password"
          spellcheck={false}
          disabled={disabled}
          value={typeof draft === "string" ? draft : ""}
          placeholder={configured ? "Configured — type to replace" : "Not configured — type to set"}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={describedBy}
          onInput={(event) => onChange((event.target as HTMLInputElement).value)}
          class={`mt-1 ${INPUT_CLASS}`}
        />
        {disabled && disabledReason ? (
          <p class="mt-1 text-[11px] font-medium text-warning-300">{disabledReason}</p>
        ) : null}
        {help}
        {failure}
      </div>
    );
  }

  if (spec.type === "boolean") {
    const checked = draft === undefined ? rawValue(value) === true : draft === true;
    return (
      <div>
        <label class="flex items-center gap-2 text-xs font-medium text-neutral-300">
          <input
            id={inputId}
            type="checkbox"
            checked={checked}
            disabled={disabled}
            aria-describedby={describedBy}
            onChange={(event) => onChange((event.target as HTMLInputElement).checked)}
            class="h-4 w-4 rounded border-neutral-600 bg-neutral-800 text-primary-600 focus:ring-1 focus:ring-primary-500"
          />
          {label}
        </label>
        {help}
        {failure}
      </div>
    );
  }

  if (spec.type === "enum") {
    const choices = spec.choices ?? [];
    const current = draft === undefined ? String(rawValue(value) ?? "") : String(draft ?? "");
    return (
      <div>
        <label for={inputId} class={LABEL_CLASS}>
          {label}
          {spec.required ? <span class="ml-1 text-neutral-500">(required)</span> : null}
        </label>
        <select
          id={inputId}
          disabled={disabled}
          value={current}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={describedBy}
          onChange={(event) => onChange((event.target as HTMLSelectElement).value)}
          class={`mt-1 ${INPUT_CLASS}`}
        >
          {current === "" ? <option value="">Choose…</option> : null}
          {choices.map((choice) => (
            <option key={choice} value={choice}>
              {choice}
            </option>
          ))}
        </select>
        {help}
        {failure}
      </div>
    );
  }

  if (spec.type === "array") {
    const items = draft === undefined ? asList(rawValue(value) ?? initialValue(spec, value)) : asList(draft);
    const atCap = spec.max_items !== undefined && items.length >= spec.max_items;
    return (
      <div>
        <span class={LABEL_CLASS}>
          {label}
          {spec.required ? <span class="ml-1 text-neutral-500">(required)</span> : null}
        </span>
        <ul class="mt-1 space-y-1.5">
          {items.map((item, index) => (
            <li key={index} class="flex items-center gap-2">
              <input
                type="text"
                value={item}
                disabled={disabled}
                aria-label={`${label} item ${index + 1}`}
                aria-describedby={describedBy}
                onInput={(event) => {
                  const next = items.slice();
                  next[index] = (event.target as HTMLInputElement).value;
                  onChange(next);
                }}
                class={INPUT_CLASS}
              />
              <button
                type="button"
                disabled={disabled}
                onClick={() => onChange(items.filter((_, at) => at !== index))}
                class="rounded px-2 py-1 text-xs text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-danger-400 disabled:opacity-40"
                title={`Remove item ${index + 1}`}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
        <button
          type="button"
          disabled={disabled || atCap}
          onClick={() => onChange([...items, ""])}
          class="mt-1.5 rounded-md border border-neutral-700 px-2 py-1 text-[11px] text-neutral-300 transition-colors hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Add item
        </button>
        {atCap ? (
          <p class="mt-1 text-[11px] text-neutral-500">
            This list already holds its {spec.max_items} items.
          </p>
        ) : null}
        {help}
        {failure}
      </div>
    );
  }

  const numeric = spec.type === "integer" || spec.type === "number";
  const current = draft === undefined ? rawValue(value) : draft;
  const text = current === undefined || current === null ? "" : String(current);
  const common = {
    id: inputId,
    value: text,
    disabled,
    "aria-invalid": error ? ("true" as const) : undefined,
    "aria-describedby": describedBy,
    class: `mt-1 ${INPUT_CLASS}`,
  };
  const onText = (event: Event) => onChange((event.target as HTMLInputElement).value);
  const onNumeric = (event: Event) => {
    const raw = (event.target as HTMLInputElement).value;
    if (raw.trim() === "") {
      onChange(undefined);
      return;
    }
    const parsed = Number(raw);
    onChange(Number.isNaN(parsed) ? undefined : parsed);
  };
  return (
    <div>
      <label for={inputId} class={LABEL_CLASS}>
        {label}
        {spec.required ? <span class="ml-1 text-neutral-500">(required)</span> : null}
      </label>
      {numeric ? (
        <input
          {...common}
          type="number"
          min={spec.minimum}
          max={spec.maximum}
          step={spec.type === "integer" ? 1 : "any"}
          onInput={onNumeric}
        />
      ) : (
        <input {...common} type="text" maxLength={spec.max_length} onInput={onText} />
      )}
      {help}
      {failure}
    </div>
  );
}

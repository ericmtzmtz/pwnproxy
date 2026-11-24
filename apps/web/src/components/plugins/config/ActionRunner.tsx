import { useId, useState } from "preact/hooks";
import { PluginConfigError, runPluginAction } from "@/api/plugins/config/calls";
import type { ActionScope, ActionSpec } from "@/api/plugins/config/types";
import { TaskPoller } from "@/components/task/TaskPoller";
import { SchemaField } from "./SchemaField";
import { bareField, humanize } from "./format";

/**
 * One action: a form built from its declared parameters, a button, and the
 * outcome.
 *
 * A short action answers inline (`200` with `result`); a long one answers `202`
 * with a `task_id`, and the existing `TaskPoller` follows the task — no second
 * polling loop. The server decides whether the call is allowed at all: an action
 * that requires `full` is disabled for an `agent` token and one on a plugin that
 * is not loaded is disabled because the API would answer `409`.
 */

interface ActionRunnerProps {
  plugin: string;
  spec: ActionSpec;
  /** Scope of the stored token, as `GET /auth/whoami` reported it. */
  scope: ActionScope;
  /** Whether this process has the plugin loaded (`409` for its actions if not). */
  pluginLoaded: boolean;
}

interface ActionFailure {
  message: string;
  field: string | null;
}

function resultText(result: unknown): string {
  if (result === undefined || result === null) return "";
  if (typeof result === "string") return result;
  try {
    return JSON.stringify(result, null, 2);
  } catch {
    return String(result);
  }
}

export function ActionRunner({ plugin, spec, scope, pluginLoaded }: ActionRunnerProps) {
  const prefix = useId();
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ActionFailure | null>(null);
  const [result, setResult] = useState<unknown>(undefined);
  const [taskId, setTaskId] = useState<string | null>(null);

  const needsFull = spec.requires_scope === "full";
  const blockedByScope = needsFull && scope !== "full";
  const disabled = busy || !pluginLoaded || blockedByScope;
  const title = humanize(spec.name);

  async function run(event: Event): Promise<void> {
    event.preventDefault();
    if (disabled) return;
    setBusy(true);
    setFailure(null);
    setResult(undefined);
    setTaskId(null);
    try {
      const parameters: Record<string, unknown> = {};
      for (const parameter of spec.parameters) {
        const value = draft[parameter.key];
        if (value !== undefined) parameters[parameter.key] = value;
      }
      const response = await runPluginAction(plugin, spec.name, parameters);
      if (response.task_id) {
        setTaskId(response.task_id);
      } else {
        setResult(response.result);
        window.dispatchEvent(
          new CustomEvent("pwnproxy-toast", {
            detail: { title: `${title} finished`, message: "The action completed.", severity: "success" },
          }),
        );
      }
    } catch (error: unknown) {
      const field = error instanceof PluginConfigError ? error.field : null;
      const message = error instanceof Error ? error.message : String(error);
      setFailure({ message, field });
      window.dispatchEvent(
        new CustomEvent("pwnproxy-toast", {
          detail: { title: `${title} failed`, message, severity: "error" },
        }),
      );
      const target = bareField(field);
      if (target) requestAnimationFrame(() => document.getElementById(`${prefix}-${target}`)?.focus());
    } finally {
      setBusy(false);
    }
  }

  const shown = resultText(result);

  return (
    <fieldset class="mt-3 rounded-md border border-neutral-800 bg-neutral-950 p-3">
      <legend class="px-1 text-xs font-semibold uppercase tracking-wider text-neutral-400">
        {title}
      </legend>
      {spec.help ? <p class="max-w-prose text-[11px] text-neutral-500">{spec.help}</p> : null}

      <form onSubmit={run} class="mt-2">
        {spec.parameters.length > 0 ? (
          <div class="grid gap-3 sm:grid-cols-2">
            {spec.parameters.map((parameter) => (
              <SchemaField
                key={parameter.key}
                spec={parameter}
                value={undefined}
                draft={draft[parameter.key]}
                idPrefix={prefix}
                disabled={busy}
                error={failure?.field && bareField(failure.field) === parameter.key ? failure.message : null}
                onChange={(value) => setDraft((previous) => ({ ...previous, [parameter.key]: value }))}
              />
            ))}
          </div>
        ) : null}

        <div class="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="submit"
            disabled={disabled}
            class="rounded-md bg-primary-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
          >
            {busy ? "Running…" : `Run ${title}`}
          </button>
          {spec.long_running ? (
            <span class="text-[11px] text-neutral-500">Long-running: the result is a task.</span>
          ) : null}
        </div>

        {!pluginLoaded ? (
          <p class="mt-2 text-[11px] text-warning-300">
            Not available: the plugin is not loaded, so the API refuses its actions with a 409. Turn
            the plugin on to run them.
          </p>
        ) : null}
        {blockedByScope ? (
          <p class="mt-2 text-[11px] text-warning-300">
            This action needs a token of scope “full”; the stored token cannot run it.
          </p>
        ) : null}
        {failure && failure.field === null ? (
          <p role="alert" class="mt-2 rounded bg-danger-900/30 px-2 py-1 text-[11px] text-danger-300">
            {failure.message}
          </p>
        ) : null}
      </form>

      {taskId ? (
        <div class="mt-3">
          <TaskPoller
            taskId={taskId}
            onComplete={(task) => setResult(task.result)}
          />
        </div>
      ) : null}

      {shown ? (
        <div class="mt-3">
          <p class="mb-1 text-[11px] font-semibold uppercase tracking-wider text-neutral-400">Result</p>
          <pre class="max-h-64 overflow-auto rounded border border-neutral-800 bg-neutral-900 p-2 font-mono text-[11px] text-neutral-200">
            {shown}
          </pre>
        </div>
      ) : null}
    </fieldset>
  );
}

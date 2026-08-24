import { useState } from "preact/hooks";
import { TaskPoller } from "@/components/task/TaskPoller";
import { generateReport, reportDownloadUrl } from "@/api/reports/calls";
import type { ReportAudience, ReportFormat, ReportResult } from "@/api/reports/types";
import type { TaskStatus } from "@/api/task/types";

const AUDIENCES: { value: ReportAudience; label: string; hint: string }[] = [
  { value: "technical", label: "Technical", hint: "Engineers — full detail per finding" },
  { value: "executive", label: "Executive", hint: "Stakeholders — business language" },
  { value: "remediation", label: "Remediation", hint: "Dev team — fix plan first" },
];

const FORMATS: { value: ReportFormat; label: string }[] = [
  { value: "md", label: "Markdown" },
  { value: "html", label: "HTML" },
  { value: "pdf", label: "PDF" },
];

export function ReportGenerator() {
  const [audience, setAudience] = useState<ReportAudience>("technical");
  const [formats, setFormats] = useState<ReportFormat[]>(["md"]);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [result, setResult] = useState<ReportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const toggleFormat = (f: ReportFormat) => {
    setFormats((prev) => (prev.includes(f) ? prev.filter((x) => x !== f) : [...prev, f]));
  };

  const start = async () => {
    setError(null);
    setResult(null);
    if (formats.length === 0) {
      setError("Select at least one format");
      return;
    }
    setStarting(true);
    try {
      const res = await generateReport({ audience, formats });
      setTaskId(res.task_id);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setStarting(false);
    }
  };

  const onComplete = (task: TaskStatus) => {
    if (task.status === "completed" && task.result) {
      setResult(task.result as ReportResult);
    }
  };

  return (
    <div class="space-y-4">
      <div>
        <div class="mb-2 text-xs font-semibold uppercase tracking-wider text-neutral-400">Audience</div>
        <div class="flex flex-wrap gap-2">
          {AUDIENCES.map((a) => (
            <button
              onClick={() => setAudience(a.value)}
              title={a.hint}
              class={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${audience === a.value ? "bg-primary-600 text-white" : "bg-neutral-800 text-neutral-400 hover:bg-neutral-700"}`}
            >
              {a.label}
            </button>
          ))}
        </div>
      </div>

      <div>
        <div class="mb-2 text-xs font-semibold uppercase tracking-wider text-neutral-400">Formats</div>
        <div class="flex flex-wrap gap-4">
          {FORMATS.map((f) => (
            <label class="flex cursor-pointer items-center gap-1.5 text-sm text-neutral-300">
              <input
                type="checkbox"
                checked={formats.includes(f.value)}
                onChange={() => toggleFormat(f.value)}
                class="h-3.5 w-3.5 rounded border-neutral-600 bg-neutral-800 accent-primary-600"
              />
              {f.label}
            </label>
          ))}
        </div>
      </div>

      <div class="flex items-center gap-3">
        <button
          onClick={start}
          disabled={starting || !!taskId}
          class={`inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition-colors ${starting || taskId ? "cursor-not-allowed bg-neutral-800 text-neutral-500" : "bg-primary-600 text-white hover:bg-primary-500"}`}
        >
          {starting ? (
            <svg class="h-4 w-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" /><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" /></svg>
          ) : null}
          Generate report
        </button>
        {error && <span class="text-xs text-danger-500">{error}</span>}
      </div>

      {taskId && !result && <TaskPoller taskId={taskId} onComplete={onComplete} />}

      {taskId && result?.files && (
        <div class="space-y-3">
          {result.flagged_groups ? (
            <p class="text-xs text-yellow-400">⚠️ {result.flagged_groups} finding group(s) contained unverified LLM references that were removed.</p>
          ) : null}
          <div class="flex flex-wrap items-center gap-2">
            <span class="text-xs font-semibold uppercase tracking-wider text-neutral-400">Download:</span>
            {Object.entries(result.files).map(([fmt, file]) => (
              <a
                href={reportDownloadUrl(taskId, fmt)}
                target="_blank"
                rel="noreferrer"
                class="inline-flex items-center gap-1.5 rounded-md bg-neutral-800 px-3 py-1.5 text-xs font-medium text-neutral-200 transition-colors hover:bg-neutral-700"
                title={file}
              >
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="h-3.5 w-3.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" x2="12" y1="15" y2="3" /></svg>
                {fmt.toUpperCase()}
              </a>
            ))}
          </div>
          <button
            onClick={() => { setTaskId(null); setResult(null); }}
            class="text-xs text-neutral-500 underline-offset-2 hover:text-neutral-300 hover:underline"
          >
            Generate another report
          </button>
        </div>
      )}
    </div>
  );
}

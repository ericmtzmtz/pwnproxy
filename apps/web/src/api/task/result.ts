import type { IntruderResult } from "@/api/intruder/types";
import type { RepeaterTaskResult, ScanFinding } from "./types";

/**
 * Readers for a task's `result` payload.
 *
 * `GET /tasks/{id}` returns `TaskStatusResponse.result` typed as `dict[str, Any]`
 * on the server, so it arrives here as `Record<string, unknown> | null`. Each
 * reader below checks the shape it reads instead of casting the payload blindly.
 */

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function itemList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function count(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function textRecord(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(record(value))) {
    if (typeof entry === "string") out[key] = entry;
  }
  return out;
}

/** Findings persisted by a `scan` task (`ExportEngine.to_dicts()`). */
export function scanFindings(result: unknown): ScanFinding[] {
  return itemList(record(result)["findings"]).map((entry) => {
    const f = record(entry);
    return {
      scanner: text(f["scanner"]),
      url: text(f["url"]),
      method: text(f["method"]),
      param_name: text(f["param_name"]),
      param_location: text(f["param_location"]),
      technique: text(f["technique"]),
      severity: text(f["severity"]),
      confidence: text(f["confidence"]),
      payload: text(f["payload"]),
      evidence: text(f["evidence"]),
    };
  });
}

/** Per-request results of an `intruder` task. */
export function intruderResults(result: unknown): IntruderResult[] {
  return itemList(record(result)["results"]).map((entry, index) => {
    const r = record(entry);
    return {
      request_id: count(r["request_id"], index),
      payload: text(r["payload"]),
      status_code: count(r["status_code"]),
      response_length: count(r["response_length"]),
      timing_ms: count(r["timing_ms"]),
      response_headers: textRecord(r["response_headers"]),
      response_body: text(r["response_body"]),
      error: typeof r["error"] === "string" ? r["error"] : null,
      // Empty for results persisted before the engine reported it.
      raw_request: text(r["raw_request"]),
    };
  });
}

/** Response stored by a `repeater` task; `null` while it has no result yet. */
export function repeaterResult(result: unknown): RepeaterTaskResult | null {
  const r = record(result);
  if (typeof r["status_code"] !== "number") return null;
  return {
    status_code: r["status_code"],
    headers: textRecord(r["headers"]),
    body: text(r["body"]),
    duration_ms: count(r["duration_ms"]),
    error: typeof r["error"] === "string" ? r["error"] : undefined,
  };
}

/** Reads a string field from a task result (e.g. the `phase` a report task publishes). */
export function resultText(result: unknown, key: string): string {
  return text(record(result)[key]);
}

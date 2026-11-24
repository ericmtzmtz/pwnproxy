/**
 * The one place in the Web UI where data from a target becomes markup.
 *
 * Everything else renders untrusted data as text: Preact escapes it in JSX and
 * the `.astro` pages build nodes with `document.createElement` plus
 * `textContent` (see `@/utils/dom`). Response bodies are the single exception,
 * because the JSON body view needs highlight spans around keys.
 *
 * `highlightBody` escapes **first** and only then writes the fixed
 * `<span class="text-sky-400">` wrapper; the body never reaches the markup
 * unescaped. `tests/architecture/test_web_xss.py` fails if that order flips,
 * if this file stops being the only escape helper, or if another HTML sink
 * appears in `apps/web/src`.
 *
 * Why it matters: the API token lives in `localStorage`, so any script running
 * on this origin owns every session, flow and finding of the proxy.
 */

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Escape the five HTML-significant characters.
 *
 * Pure string work on purpose (no `div.textContent` round-trip): it runs during
 * SSR too, and it escapes quotes so the result is also safe inside attributes.
 */
export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char);
}

/**
 * A response body as inert text, with JSON keys wrapped in a highlight span.
 *
 * The body is matched in its raw form and every slice is escaped before being
 * appended, so the only markup that can come out of here is the wrapper this
 * function writes itself.
 */
export function highlightBody(body: string, contentType: string): string {
  if (!contentType.includes("json")) return escapeHtml(body);

  // Matches a JSON object key, quotes and colon included: `"name":`.
  const jsonKey = /"([^"]+)":/g;
  const out: string[] = [];
  let cursor = 0;
  for (const match of body.matchAll(jsonKey)) {
    const start = match.index ?? 0;
    out.push(escapeHtml(body.slice(cursor, start)));
    // `match[0]` is `"key":`; keep the colon outside the span, as before.
    out.push(`<span class="text-sky-400">${escapeHtml(match[0].slice(0, -1))}</span>:`);
    cursor = start + match[0].length;
  }
  out.push(escapeHtml(body.slice(cursor)));
  return out.join("");
}

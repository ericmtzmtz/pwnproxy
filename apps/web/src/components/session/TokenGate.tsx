import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import { UNAUTHORIZED_EVENT, clearToken, getToken, setToken } from "@/api/client";
import { whoAmI } from "@/api/auth/calls";

/** The command that prints the token (and a URL that opens this screen with it). */
const TOKEN_COMMAND = "pwnproxy api token";

/** Single-instance heading id: the dialog is mounted once, in the base layout. */
const TITLE_ID = "token-gate-title";

/**
 * Full-screen «Paste the token» gate.
 *
 * Mounted once in `layouts/Base.astro`, so it covers every route: the API
 * requires a token and nothing in the UI can talk to it without one. It shows
 * up when there is no stored token and whenever a request or socket reports the
 * token is no longer accepted ({@link UNAUTHORIZED_EVENT}); a valid token
 * reloads the page so every island fetches its data again.
 *
 * A native `<dialog>` opened with `showModal()` gives the inert page, focus
 * containment and top layer for free, and `closedby="none"` plus a prevented
 * `cancel` keep `Esc` from dismissing a gate the user has to answer.
 */
export function TokenGate() {
  const [blocked, setBlocked] = useState(() => !getToken());
  const [value, setValue] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const copiedTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onUnauthorized = () => {
      setBlocked(true);
      setBusy(false);
      setValue("");
      setError("The token this tab was using is no longer accepted. Paste the current one.");
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog) {
      if (blocked && !dialog.open) dialog.showModal();
      if (!blocked && dialog.open) dialog.close();
    }
    // The pre-hydration script in Base.astro sets the same class; this keeps it
    // in charge of hiding `main` once the gate closed in-page.
    document.documentElement.classList.toggle("needs-token", blocked);
  }, [blocked]);

  useEffect(() => () => {
    if (copiedTimer.current) clearTimeout(copiedTimer.current);
  }, []);

  const copyCommand = useCallback(async () => {
    try {
      await navigator.clipboard?.writeText(TOKEN_COMMAND);
      setCopied(true);
      if (copiedTimer.current) clearTimeout(copiedTimer.current);
      copiedTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard blocked (permissions/insecure context): the text is selectable.
    }
  }, []);

  const submit = useCallback(
    async (event: Event) => {
      event.preventDefault();
      const token = value.trim();
      if (token.length === 0) {
        setError("Paste the token to continue.");
        return;
      }

      setBusy(true);
      setError(null);
      setToken(token);

      try {
        await whoAmI();
        window.location.reload();
      } catch (err) {
        clearToken();
        setBusy(false);
        if (err instanceof Error && err.name === "TypeError") {
          setError("Could not reach the pwnproxy API on its usual port. Is it running?");
        } else {
          setError(err instanceof Error ? err.message : "The token could not be verified.");
        }
      }
    },
    [value],
  );

  const canSubmit = !busy && value.trim().length > 0;

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={TITLE_ID}
      {...({ closedby: "none" } as Record<string, string>)}
      onCancel={(event) => event.preventDefault()}
      class="m-auto w-full max-w-md border-0 bg-transparent p-6 text-neutral-100 backdrop:bg-neutral-950/95 backdrop:backdrop-blur-sm"
    >
      <div class="mb-5 flex items-center gap-2">
        <span class="inline-flex h-5 w-5 items-center justify-center rounded-sm bg-primary-500 text-[10px] font-bold text-white">
          P
        </span>
        <span class="text-base font-bold tracking-tight text-neutral-50">pwnproxy</span>
        <span class="ml-auto rounded-sm border border-neutral-800 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-neutral-500">
          Locked
        </span>
      </div>

      <div class="rounded-lg border border-neutral-800 bg-neutral-900 p-6 shadow-lg">
        <div class="flex items-start gap-3">
          <span class="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-primary-900/40 text-primary-300">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              class="h-5 w-5"
              aria-hidden="true"
            >
              <circle cx="7.5" cy="15.5" r="4.5" />
              <path d="m10.7 12.3 8.8-8.8" />
              <path d="m16.5 6.5 3 3" />
              <path d="m19 4 3 3" />
            </svg>
          </span>
          <div class="min-w-0">
            <h1 id={TITLE_ID} class="text-base font-semibold text-neutral-50">
              Paste the token
            </h1>
            <p class="mt-1 text-sm leading-relaxed text-neutral-400">
              This UI drives the local pwnproxy API, which only answers requests that carry a
              token. Print the token with:
            </p>
          </div>
        </div>

        <div class="mt-4 flex items-center gap-2 rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2">
          <code class="min-w-0 flex-1 truncate font-mono text-xs text-primary-300">
            {TOKEN_COMMAND}
          </code>
          <button
            type="button"
            onClick={copyCommand}
            class="shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium text-neutral-500 transition-colors hover:bg-neutral-800 hover:text-neutral-200"
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <p class="mt-2 text-xs leading-relaxed text-neutral-500">
          It also prints a link that opens this page with the token already in place.
        </p>

        {error && (
          <div
            role="alert"
            class="mt-4 flex items-start gap-2 rounded-md border border-danger-800 bg-danger-900/20 px-3 py-2"
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
              class="mt-0.5 h-4 w-4 shrink-0 text-danger-400"
              aria-hidden="true"
            >
              <path d="M12 9v4" />
              <path d="M12 17h.01" />
              <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
            </svg>
            <p class="text-xs leading-relaxed text-danger-300">{error}</p>
          </div>
        )}

        <form onSubmit={submit} class="mt-5">
          <span class="block text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
            API token
          </span>
          <div class="mt-1.5 flex items-stretch gap-2">
            <input
              // Preact's input props are a discriminated union on `type`, so a
              // `"text" | "password"` value fits no branch; the cast keeps the
              // reveal toggle instead of dropping it.
              {...({ type: revealed ? "text" : "password" } as any)}
              value={value}
              onInput={(e) => setValue((e.target as HTMLInputElement).value)}
              aria-label="API token"
              aria-invalid={error ? "true" : undefined}
              autocomplete="off"
              autocapitalize="off"
              spellcheck={false}
              autofocus
              placeholder="Paste the token here"
              disabled={busy}
              class="min-w-0 flex-1 rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 font-mono text-xs text-neutral-100 placeholder:text-neutral-600 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 disabled:opacity-60"
            />
            <button
              type="button"
              onClick={() => setRevealed((v) => !v)}
              aria-pressed={revealed}
              aria-label={revealed ? "Hide token" : "Show token"}
              class="rounded-md border border-neutral-700 px-2.5 text-[11px] font-medium text-neutral-400 transition-colors hover:bg-neutral-800 hover:text-neutral-200"
            >
              {revealed ? "Hide" : "Show"}
            </button>
          </div>

          <button
            type="submit"
            disabled={!canSubmit}
            aria-busy={busy}
            class="mt-4 w-full rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-900 disabled:text-primary-400"
          >
            {busy ? "Checking…" : "Unlock"}
          </button>
          <p class="sr-only" role="status">
            {busy ? "Checking the token" : ""}
          </p>
        </form>
      </div>
    </dialog>
  );
}

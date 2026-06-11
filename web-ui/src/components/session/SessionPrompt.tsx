import { useEffect, useState } from "preact/hooks";
import { listSessions, loadSession, createSession } from "@/api/session/calls";
import type { SessionSummary } from "@/api/session/types";

interface SessionPromptProps {
  onReady: () => void;
}

function formatDate(s: string | null): string {
  if (!s) return "-";
  return s.slice(0, 19).replace("T", " ");
}

function formatCount(n: number): string {
  if (n === 0) return "0";
  if (n < 1024) return `${n}B`;
  return `${(n / 1024).toFixed(1)}KB`;
}

export function SessionPrompt({ onReady }: SessionPromptProps) {
  const [sessions, setSessions] = useState<SessionSummary[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    listSessions()
      .then((data) => {
        setSessions(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  const handleLoad = async (name: string) => {
    try {
      await loadSession(name);
      localStorage.setItem("session-active", name);
      onReady();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleCreate = async (e: Event) => {
    e.preventDefault();
    const name = newName.trim();
    if (!name) return;
    setCreating(true);
    try {
      await createSession(name);
      localStorage.setItem("session-active", name);
      onReady();
    } catch (err: any) {
      setError(err.message);
      setCreating(false);
    }
  };

  if (loading) {
    return (
      <div class="flex min-h-screen items-center justify-center bg-neutral-950">
        <div class="flex flex-col items-center gap-3">
          <svg class="h-8 w-8 animate-spin text-primary-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
          <span class="text-sm text-neutral-400">Loading sessions...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div class="flex min-h-screen items-center justify-center bg-neutral-950">
        <div class="rounded-lg border border-red-800 bg-red-900/20 p-6 text-center">
          <p class="text-sm font-medium text-danger-500">Connection error</p>
          <p class="mt-1 text-xs text-neutral-400">{error}</p>
          <button onClick={() => window.location.reload()} class="mt-4 rounded-md bg-primary-600 px-4 py-2 text-xs font-medium text-white hover:bg-primary-500">Retry</button>
        </div>
      </div>
    );
  }

  if (sessions && sessions.length > 0) {
    return (
      <div class="flex min-h-screen items-center justify-center bg-neutral-950 p-6">
        <div class="w-full max-w-lg">
          <div class="mb-6 text-center">
            <h1 class="text-xl font-bold text-neutral-50">pwnproxy</h1>
            <p class="mt-1 text-sm text-neutral-400">Select a session to continue</p>
          </div>
          <div class="space-y-2">
            {sessions.map((s) => (
              <button
                key={s.name}
                onClick={() => handleLoad(s.name)}
                class={`w-full rounded-lg border p-4 text-left transition-colors hover:border-primary-500 hover:bg-neutral-900 ${s.last_active ? "border-primary-600 bg-neutral-900" : "border-neutral-800 bg-neutral-950"}`}
              >
                <div class="flex items-center justify-between">
                  <span class="font-medium text-neutral-100">{s.name}</span>
                  {s.last_active && <span class="rounded-full bg-primary-900/40 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-primary-400">Last used</span>}
                </div>
                <div class="mt-1 flex gap-4 text-xs text-neutral-500">
                  <span>{formatDate(s.created_at)}</span>
                  <span>{formatCount(s.request_count)} traffic</span>
                  <span>{formatCount(s.finding_count)} findings</span>
                </div>
              </button>
            ))}
          </div>
          <div class="mt-6 border-t border-neutral-800 pt-4">
            <p class="mb-2 text-center text-xs text-neutral-500">or start fresh</p>
            <form onSubmit={handleCreate} class="flex gap-2">
              <input
                value={newName}
                onInput={(e) => setNewName((e.target as HTMLInputElement).value)}
                placeholder="Session name"
                class="flex-1 rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 placeholder-neutral-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
              />
              <button
                type="submit"
                disabled={creating || !newName.trim()}
                class="rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
              >
                {creating ? "Creating..." : "Create"}
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div class="flex min-h-screen items-center justify-center bg-neutral-950 p-6">
      <div class="w-full max-w-sm text-center">
        <h1 class="text-xl font-bold text-neutral-50">pwnproxy</h1>
        <p class="mt-1 text-sm text-neutral-400">No sessions found. Create one to get started.</p>
        <form onSubmit={handleCreate} class="mt-6 flex gap-2">
          <input
            value={newName}
            onInput={(e) => setNewName((e.target as HTMLInputElement).value)}
            placeholder="Session name"
            class="flex-1 rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 placeholder-neutral-500 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <button
            type="submit"
            disabled={creating || !newName.trim()}
            class="rounded-md bg-primary-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:bg-primary-800 disabled:text-primary-400"
          >
            {creating ? "Creating..." : "Create"}
          </button>
        </form>
      </div>
    </div>
  );
}

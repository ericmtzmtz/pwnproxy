import { useEffect, useState } from "preact/hooks";
import { TOKEN_CHANGED_EVENT, getToken } from "@/api/client";
import { SessionPrompt } from "@/components/session/SessionPrompt";
import { Dashboard } from "@/components/dashboard/Dashboard";

function hasStoredSession(): boolean {
  try {
    return !!localStorage.getItem("session-active");
  } catch {
    return false;
  }
}

export function AppShell() {
  const [hasSession, setHasSession] = useState<boolean | null>(null);
  const [hasToken, setHasToken] = useState(false);

  useEffect(() => {
    const syncToken = () => setHasToken(Boolean(getToken()));
    syncToken();
    window.addEventListener(TOKEN_CHANGED_EVENT, syncToken);
    setHasSession(hasStoredSession());
    try { (window as any).__sessionReady?.(); } catch {}
    return () => window.removeEventListener(TOKEN_CHANGED_EVENT, syncToken);
  }, []);

  const handleReady = () => {
    setHasSession(true);
    const redirect = sessionStorage.getItem("redirect-after-session");
    if (redirect) {
      sessionStorage.removeItem("redirect-after-session");
      window.location.replace(redirect);
    }
  };

  // Token first, session second: without a token nothing behind this shell may
  // run (the gate owns the screen and no session request is sent).
  if (!hasToken) return null;

  if (hasSession === null) {
    return (
      <div class="flex min-h-screen items-center justify-center bg-neutral-950">
        <div class="flex flex-col items-center gap-3">
          <svg class="h-8 w-8 animate-spin text-primary-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
          <span class="text-sm text-neutral-400">Loading...</span>
        </div>
      </div>
    );
  }

  if (!hasSession) {
    return <SessionPrompt onReady={handleReady} />;
  }

  return <Dashboard />;
}

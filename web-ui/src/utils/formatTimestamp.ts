export function formatTimestamp(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts.endsWith("Z") ? ts : ts + "+00:00");
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export function formatTimeOnly(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts.endsWith("Z") ? ts : ts + "+00:00");
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString();
}

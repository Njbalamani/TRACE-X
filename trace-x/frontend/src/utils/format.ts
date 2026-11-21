export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function shortHash(h: string | null | undefined, n = 12): string {
  return h ? `${h.slice(0, n)}…` : "—";
}

export function fmtTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  return ts.replace("T", " ").replace("Z", "").slice(0, 19);
}

export function timeOnly(ts: string | null | undefined): string {
  if (!ts) return "--:--";
  const m = ts.match(/(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : ts.slice(0, 19);
}

export function cls(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

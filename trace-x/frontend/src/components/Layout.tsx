// App shell: sidebar navigation + global search + AI-mode indicator.
import { ReactNode, useEffect, useRef, useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import {
  Search, LayoutDashboard, FolderSearch, FileDigit, Clock, ShieldAlert, GitBranch,
  ShieldCheck, FileText, Settings, Radar, Cpu,
} from "lucide-react";
import { api } from "../services/api";
import { cls } from "../utils/format";
import type { SearchHit, SystemInfo } from "../types";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/investigations", label: "Investigations", icon: FolderSearch },
  { to: "/evidence", label: "Evidence", icon: FileDigit },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/integrity", label: "Integrity", icon: ShieldCheck },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function Layout({ children }: { children: ReactNode }) {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<SearchHit[] | null>(null);
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [searching, setSearching] = useState(false);
  const navigate = useNavigate();
  const timer = useRef<number | null>(null);

  useEffect(() => {
    api.get<SystemInfo>("/system/info").then(setInfo).catch(() => {});
  }, []);

  useEffect(() => {
    if (timer.current) window.clearTimeout(timer.current);
    if (q.trim().length < 2) { setHits(null); return; }
    timer.current = window.setTimeout(async () => {
      setSearching(true);
      try {
        const r = await api.get<{ items: SearchHit[] }>(`/search?q=${encodeURIComponent(q.trim())}`);
        setHits(r.items);
      } catch { setHits([]); }
      setSearching(false);
    }, 300);
  }, [q]);

  const goHit = (h: SearchHit) => {
    setQ(""); setHits(null);
    if (h.kind === "investigation") navigate(`/cases/${h.investigation_id}/overview`);
    else if (h.kind === "evidence") navigate(`/cases/${h.investigation_id}/evidence`);
    else if (h.kind === "event") navigate(`/cases/${h.investigation_id}/timeline`);
    else if (h.kind === "finding") navigate(`/cases/${h.investigation_id}/findings`);
  };

  const kindTone: Record<string, string> = {
    investigation: "text-cyan-300", evidence: "text-sky-300",
    event: "text-violet-300", finding: "text-rose-300",
  };

  return (
    <div className="min-h-screen bg-base-950">
      <div className="flex">
        {/* Sidebar */}
        <aside className="fixed inset-y-0 left-0 z-40 flex w-16 flex-col border-r border-base-700 bg-base-900 lg:w-60">
          <Link to="/" className="flex items-center gap-2.5 border-b border-base-700 px-4 py-4">
            <div className="rounded-md bg-accent-dim p-1.5"><Radar size={20} className="text-cyan-300" /></div>
            <div className="hidden lg:block">
              <div className="text-base font-bold tracking-wide text-slate-100">TRACE-X</div>
              <div className="text-[10px] text-slate-500">CYBER INVESTIGATION</div>
            </div>
          </Link>
          <nav className="flex-1 space-y-0.5 px-2 py-3">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink key={to} to={to} end={end}
                className={({ isActive }) => cls(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium",
                  isActive ? "bg-accent-dim/30 text-cyan-200" : "text-slate-400 hover:bg-base-800 hover:text-slate-200",
                )}>
                <Icon size={18} className="shrink-0" />
                <span className="hidden lg:inline">{label}</span>
              </NavLink>
            ))}
          </nav>
          <div className="border-t border-base-700 p-3">
            <div className={cls("flex items-center gap-2 rounded-md px-2.5 py-2 text-[11px]",
              info?.ai_provider_mode === "external"
                ? "bg-amber-500/10 text-amber-300" : "bg-emerald-500/10 text-emerald-300")}>
              <Cpu size={14} />
              <span className="hidden lg:inline leading-tight">
                {info?.ai_provider_mode === "external"
                  ? `External AI: ${info?.ai_provider}` : "Local deterministic AI"}
              </span>
            </div>
          </div>
        </aside>

        {/* Main */}
        <div className="ml-16 flex-1 lg:ml-60">
          {/* Topbar */}
          <header className="sticky top-0 z-30 border-b border-base-700 bg-base-900/95 backdrop-blur">
            <div className="relative mx-auto max-w-7xl px-4 py-3 sm:px-6">
              <div className="relative">
                <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search evidence ID, filename, IP, user, domain, URL, event, finding, hash…"
                  className="input pl-9"
                />
                {searching && <div className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500">…</div>}
              </div>
              {hits !== null && (
                <div className="absolute inset-x-4 top-full mt-1 card max-h-96 overflow-y-auto sm:inset-x-6">
                  {hits.length === 0 && <div className="px-4 py-3 text-sm text-slate-500">No matches for “{q}”.</div>}
                  {hits.map((h) => (
                    <button key={`${h.kind}-${h.id}`} onClick={() => goHit(h)}
                      className="flex w-full items-center gap-3 border-b border-base-800 px-4 py-2.5 text-left hover:bg-base-800">
                      <span className={cls("font-mono text-xs uppercase", kindTone[h.kind])}>{h.kind}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-slate-200">{h.code} · {h.title}</span>
                        <span className="block truncate text-xs text-slate-500">{h.detail}</span>
                      </span>
                      {h.investigation_code && (
                        <span className="shrink-0 font-mono text-[11px] text-cyan-400">{h.investigation_code}</span>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </header>
          <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6" onClick={() => { setHits(null); }}>
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}

export { Clock, GitBranch };

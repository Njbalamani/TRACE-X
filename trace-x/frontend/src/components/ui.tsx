// Shared UI primitives: badges, cards, modal, spinner, empty/error states.
import { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Loader2, XCircle, X } from "lucide-react";
import { cls } from "../utils/format";
import type { Classification, Confidence, Severity } from "../types";

export function SeverityBadge({ value }: { value: Severity | string | null }) {
  const v = (value ?? "").toLowerCase();
  const tone = v === "critical" ? "bg-rose-500/15 text-rose-300 border border-rose-500/40"
    : v === "high" ? "bg-orange-500/15 text-orange-300 border border-orange-500/40"
    : v === "medium" ? "bg-amber-500/15 text-amber-300 border border-amber-500/40"
    : v === "low" ? "bg-sky-500/15 text-sky-300 border border-sky-500/40"
    : "bg-slate-600/20 text-slate-400 border border-slate-600";
  return <span className={cls("chip uppercase", tone)}>{value ?? "—"}</span>;
}

export function ConfidenceBadge({ value }: { value: Confidence | string | null }) {
  const v = (value ?? "").toLowerCase();
  const tone = v === "high" ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40"
    : v === "medium" ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/40"
    : "bg-slate-600/20 text-slate-400 border border-slate-600";
  return <span className={cls("chip uppercase", tone)}>{value ?? "—"}</span>;
}

export function ClassificationBadge({ value }: { value: Classification | string | null }) {
  const v = (value ?? "").toLowerCase();
  const tone = v === "confirmed" ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40"
    : v === "likely" ? "bg-amber-500/15 text-amber-300 border border-amber-500/40"
    : v === "possible" ? "bg-violet-500/15 text-violet-300 border border-violet-500/40"
    : "bg-slate-600/20 text-slate-400 border border-slate-600";
  return <span className={cls("chip uppercase", tone)}>{value ?? "—"}</span>;
}

export function IntegrityBadge({ status }: { status: string | null | undefined }) {
  const s = (status ?? "").toLowerCase();
  if (s === "verified")
    return <span className="chip border border-emerald-500/40 bg-emerald-500/15 text-emerald-300"><CheckCircle2 size={11} /> INTEGRITY VERIFIED</span>;
  if (s === "violation")
    return <span className="chip border border-rose-500/50 bg-rose-500/15 text-rose-300 animate-pulse"><AlertTriangle size={11} /> INTEGRITY VIOLATION</span>;
  if (s === "missing")
    return <span className="chip border border-orange-500/50 bg-orange-500/15 text-orange-300"><XCircle size={11} /> FILE MISSING</span>;
  return <span className="chip border border-slate-600 bg-slate-600/20 text-slate-400">UNKNOWN</span>;
}

export function EventBadge({ type }: { type: string }) {
  const v = type.toLowerCase();
  const tone = v.includes("failure") ? "text-rose-300 bg-rose-500/10 border-rose-500/30"
    : v.includes("success") ? "text-emerald-300 bg-emerald-500/10 border-emerald-500/30"
    : v.includes("privilege") ? "text-orange-300 bg-orange-500/10 border-orange-500/30"
    : v.includes("transfer") || v.includes("exfil") ? "text-fuchsia-300 bg-fuchsia-500/10 border-fuchsia-500/30"
    : v.includes("file") ? "bg-sky-500/10 text-sky-300 border-sky-500/30"
    : v.includes("email") ? "bg-violet-500/10 text-violet-300 border-violet-500/30"
    : v.includes("network") || v.includes("connection") ? "bg-cyan-500/10 text-cyan-300 border-cyan-500/30"
    : "bg-slate-600/20 text-slate-400 border-slate-600";
  return <span className={cls("chip font-mono border", tone)}>{type}</span>;
}

export function StatCard({ label, value, icon, tone = "cyan", sub }: {
  label: string; value: ReactNode; icon: ReactNode; tone?: string; sub?: string;
}) {
  const tones: Record<string, string> = {
    cyan: "text-cyan-300 bg-cyan-500/10",
    rose: "text-rose-300 bg-rose-500/10",
    amber: "text-amber-300 bg-amber-500/10",
    emerald: "text-emerald-300 bg-emerald-500/10",
    violet: "text-violet-300 bg-violet-500/10",
    orange: "text-orange-300 bg-orange-500/10",
    sky: "text-sky-300 bg-sky-500/10",
  };
  return (
    <div className="card p-4 flex items-start gap-3">
      <div className={cls("rounded-md p-2", tones[tone] ?? tones.cyan)}>{icon}</div>
      <div className="min-w-0">
        <div className="text-2xl font-bold text-slate-100 leading-tight">{value}</div>
        <div className="text-xs text-slate-400 uppercase tracking-wide">{label}</div>
        {sub && <div className="text-[11px] text-slate-500 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-slate-400 text-sm">
      <Loader2 className="animate-spin" size={16} /> {label}…
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200 flex items-start gap-2">
      <AlertTriangle size={16} className="mt-0.5 shrink-0" />
      <div>
        <div className="font-semibold">Something went wrong</div>
        <div className="text-rose-300/90">{message}</div>
      </div>
    </div>
  );
}

export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <div className="text-slate-500">{icon}</div>
      <div className="text-sm font-medium text-slate-400">{title}</div>
      {hint && <div className="text-xs text-slate-500 max-w-sm">{hint}</div>}
    </div>
  );
}

export function Modal({ title, onClose, children, wide }: {
  title: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 sm:p-8"
      onClick={onClose}>
      <div className={cls("card w-full", wide ? "max-w-4xl" : "max-w-2xl")}
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-base-700 px-5 py-3">
          <div className="font-semibold text-slate-100">{title}</div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:bg-base-700 hover:text-slate-200">
            <X size={18} />
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  );
}

export function KV({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-2 text-sm py-1">
      <span className="w-36 shrink-0 text-slate-500">{label}</span>
      <span className={cls("text-slate-200 min-w-0 break-all", mono && "font-mono text-xs")}>{children}</span>
    </div>
  );
}

export function SectionTitle({ icon, children }: { icon?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-400 mb-3">
      {icon}{children}
    </div>
  );
}

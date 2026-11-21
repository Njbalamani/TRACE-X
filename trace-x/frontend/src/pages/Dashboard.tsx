import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  FolderSearch, FileDigit, ShieldAlert, AlertTriangle, Activity, CheckCircle2, Zap,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { api } from "../services/api";
import { ErrorBox, IntegrityBadge, SeverityBadge, Spinner, StatCard } from "../components/ui";
import { fmtTime, shortHash } from "../utils/format";
import type { DashboardStats } from "../types";

export default function Dashboard() {
  const [data, setData] = useState<DashboardStats | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.get<DashboardStats>("/dashboard").then(setData).catch((e) => setErr(e.message));
  }, []);

  if (err) return <ErrorBox message={err} />;
  if (!data) return <Spinner label="Loading dashboard" />;

  const sevData = Object.entries(data.findings_by_severity).map(([name, count]) => ({ name, count }));
  const typeData = Object.entries(data.suspicious_by_type)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
  const sevColor: Record<string, string> = { Critical: "#f43f5e", High: "#fb923c", Medium: "#fbbf24", Low: "#38bdf8" };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100">SOC Dashboard</h1>
        <p className="text-sm text-slate-500">Investigation overview across all cases</p>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Total Investigations" value={data.total_investigations} icon={<FolderSearch size={18} />} tone="cyan" />
        <StatCard label="Active" value={data.active_investigations} icon={<Activity size={18} />} tone="sky" sub="Open + Investigating" />
        <StatCard label="Evidence Items" value={data.evidence_items} icon={<FileDigit size={18} />} tone="violet" />
        <StatCard label="Suspicious Events" value={data.suspicious_events} icon={<Zap size={18} />} tone="amber" />
        <StatCard label="Critical Findings" value={data.critical_findings} icon={<ShieldAlert size={18} />} tone="rose" sub="High + Critical" />
        <StatCard label="Integrity Violations" value={data.integrity_violations}
          icon={data.integrity_violations > 0 ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
          tone={data.integrity_violations > 0 ? "rose" : "emerald"} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card p-4">
          <div className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Findings by Severity</div>
          {sevData.length === 0 ? <div className="py-8 text-center text-sm text-slate-500">No findings yet</div> : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={sevData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                <YAxis allowDecimals={false} stroke="#64748b" fontSize={12} width={28} />
                <Tooltip contentStyle={{ background: "#0e1726", border: "1px solid #27395a", borderRadius: 6, color: "#e2e8f0" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {sevData.map((d) => <Cell key={d.name} fill={sevColor[d.name] ?? "#22d3ee"} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="card p-4">
          <div className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Suspicious Events by Type</div>
          {typeData.length === 0 ? <div className="py-8 text-center text-sm text-slate-500">No suspicious events yet</div> : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={typeData} layout="vertical">
                <XAxis type="number" allowDecimals={false} stroke="#64748b" fontSize={12} />
                <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} width={140} />
                <Tooltip contentStyle={{ background: "#0e1726", border: "1px solid #27395a", borderRadius: 6, color: "#e2e8f0" }} />
                <Bar dataKey="count" fill="#22d3ee" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="card overflow-hidden">
          <div className="border-b border-base-700 px-4 py-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Recent Investigations</div>
          <table className="w-full">
            <tbody>
              {data.recent_investigations.length === 0 && (
                <tr><td className="td text-slate-500" colSpan={4}>No investigations yet — create one to begin.</td></tr>
              )}
              {data.recent_investigations.map((inv) => (
                <tr key={inv.id} className="border-b border-base-800 hover:bg-base-800">
                  <td className="td">
                    <Link to={`/cases/${inv.id}/overview`} className="font-mono text-xs text-cyan-300 hover:underline">{inv.code}</Link>
                    <div className="truncate text-slate-300">{inv.name}</div>
                  </td>
                  <td className="td"><SeverityBadge value={inv.severity} /></td>
                  <td className="td text-xs text-slate-400">{inv.status}</td>
                  <td className="td text-xs text-slate-500">{fmtTime(inv.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card overflow-hidden">
          <div className="border-b border-base-700 px-4 py-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Recent Evidence</div>
          <table className="w-full">
            <tbody>
              {data.recent_evidence.length === 0 && (
                <tr><td className="td text-slate-500" colSpan={4}>No evidence uploaded yet.</td></tr>
              )}
              {data.recent_evidence.map((ev) => (
                <tr key={ev.id} className="border-b border-base-800 hover:bg-base-800">
                  <td className="td">
                    <span className="font-mono text-xs text-sky-300">{ev.code}</span>
                    <div className="truncate">{ev.original_filename}</div>
                  </td>
                  <td className="td">
                    <Link to={`/cases/${ev.investigation_id}/evidence`} className="font-mono text-xs text-cyan-300 hover:underline">
                      {ev.investigation_code}
                    </Link>
                  </td>
                  <td className="td font-mono text-[11px] text-slate-500">{shortHash(ev.sha256)}</td>
                  <td className="td"><IntegrityBadge status={ev.integrity_status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

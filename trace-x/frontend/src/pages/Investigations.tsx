import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { FolderPlus, Loader2 } from "lucide-react";
import { api } from "../services/api";
import { ErrorBox, IntegrityBadge, Modal, SeverityBadge, Spinner } from "../components/ui";
import { fmtTime } from "../utils/format";
import { CASE_STATUSES, INCIDENT_TYPES, SEVERITIES, type Investigation } from "../types";

export default function Investigations() {
  const [items, setItems] = useState<Investigation[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");

  const load = () => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (severity) params.set("severity", severity);
    if (q) params.set("q", q);
    api.get<{ items: Investigation[] }>(`/investigations?${params}`)
      .then((r) => setItems(r.items)).catch((e) => setErr(e.message));
  };
  useEffect(load, [status, severity, q]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Investigations</h1>
          <p className="text-sm text-slate-500">Create and manage cyber investigation cases</p>
        </div>
        <button className="btn-primary" onClick={() => setShowCreate(true)}>
          <FolderPlus size={15} /> New Investigation
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        <select className="input max-w-44" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {CASE_STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="input max-w-44" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <input className="input max-w-64" placeholder="Search by name…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      {err && <ErrorBox message={err} />}
      {!items && !err && <Spinner label="Loading investigations" />}

      {items && (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[860px]">
            <thead className="border-b border-base-700 bg-base-800/60">
              <tr>
                <th className="th">Investigation</th>
                <th className="th">Type</th>
                <th className="th">Severity</th>
                <th className="th">Status</th>
                <th className="th">Evidence</th>
                <th className="th">Events</th>
                <th className="th">Suspicious</th>
                <th className="th">Findings</th>
                <th className="th">Integrity</th>
                <th className="th">Updated</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && <tr><td className="td text-slate-500" colSpan={10}>No investigations match.</td></tr>}
              {items.map((inv) => (
                <tr key={inv.id} className="border-b border-base-800 hover:bg-base-800">
                  <td className="td">
                    <Link to={`/cases/${inv.id}/overview`} className="font-mono text-xs text-cyan-300 hover:underline">{inv.code}</Link>
                    <div className="max-w-64 truncate">{inv.name}</div>
                    <div className="text-[11px] text-slate-500">{inv.investigator || "unassigned"}</div>
                  </td>
                  <td className="td text-xs">{inv.incident_type}</td>
                  <td className="td"><SeverityBadge value={inv.severity} /></td>
                  <td className="td text-xs uppercase tracking-wide text-slate-400">{inv.status}</td>
                  <td className="td">{inv.evidence_count}</td>
                  <td className="td">{inv.event_count}</td>
                  <td className="td text-amber-300">{inv.suspicious_event_count}</td>
                  <td className="td">{inv.finding_count}</td>
                  <td className="td"><IntegrityBadge status={inv.integrity_status === "Verified" ? "verified" : "violation"} /></td>
                  <td className="td text-xs text-slate-500">{fmtTime(inv.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreated={() => { setShowCreate(false); load(); }} />}
    </div>
  );
}

function CreateModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    name: "", description: "", investigator: "", incident_type: "Account Compromise",
    severity: "Medium", status: "Open",
  });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      await api.post("/investigations", form);
      onCreated();
    } catch (e: any) {
      setErr(e.message);
      setBusy(false);
    }
  };

  return (
    <Modal title="New Investigation" onClose={onClose}>
      <div className="space-y-3">
        {err && <ErrorBox message={err} />}
        <div>
          <label className="mb-1 block text-xs text-slate-400">Investigation name *</label>
          <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="e.g. Suspicious activity — finance dept" />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">Case description</label>
          <textarea className="input" rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
            placeholder="What is being investigated?" />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="mb-1 block text-xs text-slate-400">Investigator</label>
            <input className="input" value={form.investigator} onChange={(e) => setForm({ ...form, investigator: e.target.value })} placeholder="Name" />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Incident type</label>
            <select className="input" value={form.incident_type} onChange={(e) => setForm({ ...form, incident_type: e.target.value })}>
              {INCIDENT_TYPES.map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Severity</label>
            <select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-400">Status</label>
            <select className="input" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              {CASE_STATUSES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button className="btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={busy || form.name.trim().length < 3} onClick={submit}>
            {busy && <Loader2 size={14} className="animate-spin" />} Create Investigation
          </button>
        </div>
      </div>
    </Modal>
  );
}

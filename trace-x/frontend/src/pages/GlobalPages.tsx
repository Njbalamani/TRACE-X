// Global cross-case pages: Evidence, Findings, Integrity, Reports, Settings.
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Cpu, Database, Download, FileText, HardDrive, Lock, RefreshCw, Server, ShieldAlert } from "lucide-react";
import { api } from "../services/api";
import { ClassificationBadge, ConfidenceBadge, IntegrityBadge, KV, SeverityBadge, Spinner, StatCard } from "../components/ui";
import { FindingDetailModal } from "../components/detail";
import { fmtTime, formatBytes, shortHash } from "../utils/format";
import type { Evidence, Finding, IntegrityResult, Investigation, Report, SystemInfo } from "../types";

/* ------------------------------------------------------------------ Evidence */
export function GlobalEvidence() {
  const [items, setItems] = useState<Evidence[] | null>(null);
  const [fileType, setFileType] = useState("");
  const [integrity, setIntegrity] = useState("");

  useEffect(() => {
    const qs = new URLSearchParams();
    if (fileType) qs.set("file_type", fileType);
    if (integrity) qs.set("integrity_status", integrity);
    api.get<{ items: Evidence[] }>(`/evidence?${qs}`).then((r) => setItems(r.items)).catch(() => setItems([]));
  }, [fileType, integrity]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-slate-100">Evidence Vault</h1>
      <div className="flex flex-wrap gap-2">
        <select className="input max-w-40" value={fileType} onChange={(e) => setFileType(e.target.value)}>
          <option value="">All types</option>
          {["log", "txt", "csv", "json", "eml", "pdf", "png", "jpg"].map((t) => <option key={t}>{t}</option>)}
        </select>
        <select className="input max-w-44" value={integrity} onChange={(e) => setIntegrity(e.target.value)}>
          <option value="">All integrity</option>
          <option value="Verified">Verified</option>
          <option value="Violation">Violation</option>
          <option value="Missing">Missing</option>
        </select>
      </div>
      {!items && <Spinner />}
      {items && (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[820px]">
            <thead className="border-b border-base-700 bg-base-800/60">
              <tr><th className="th">Evidence</th><th className="th">Case</th><th className="th">Type</th>
                <th className="th">Size</th><th className="th">SHA-256</th><th className="th">Events</th>
                <th className="th">Integrity</th><th className="th">Uploaded</th></tr>
            </thead>
            <tbody>
              {items.length === 0 && <tr><td className="td text-slate-500" colSpan={8}>No evidence found.</td></tr>}
              {items.map((ev) => (
                <tr key={ev.id} className="border-b border-base-800 hover:bg-base-800">
                  <td className="td">
                    <span className="font-mono text-xs text-sky-300">{ev.code}</span>
                    <div className="max-w-56 truncate">{ev.original_filename}</div>
                  </td>
                  <td className="td">
                    {ev.investigation_code && (
                      <Link className="font-mono text-xs text-cyan-300 hover:underline" to={`/cases/${ev.investigation_id}/evidence`}>
                        {ev.investigation_code}
                      </Link>
                    )}
                  </td>
                  <td className="td text-xs uppercase">{ev.file_type}</td>
                  <td className="td text-xs">{formatBytes(ev.size)}</td>
                  <td className="td font-mono text-[11px] text-slate-500">{shortHash(ev.sha256, 14)}</td>
                  <td className="td">{ev.event_count}</td>
                  <td className="td"><IntegrityBadge status={ev.integrity_status} /></td>
                  <td className="td text-xs text-slate-500">{fmtTime(ev.uploaded_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ Findings */
export function GlobalFindings() {
  const [items, setItems] = useState<Finding[] | null>(null);
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");
  const [open, setOpen] = useState<Finding | null>(null);

  useEffect(() => {
    const qs = new URLSearchParams();
    if (severity) qs.set("severity", severity);
    if (confidence) qs.set("confidence", confidence);
    api.get<{ items: Finding[] }>(`/findings?${qs}`).then((r) => setItems(r.items)).catch(() => setItems([]));
  }, [severity, confidence]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-slate-100">All Findings</h1>
      <div className="flex flex-wrap gap-2">
        <select className="input max-w-40" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>{["Low", "Medium", "High", "Critical"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="input max-w-40" value={confidence} onChange={(e) => setConfidence(e.target.value)}>
          <option value="">All confidence</option>{["Low", "Medium", "High"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      {!items && <Spinner />}
      {items && (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[820px]">
            <thead className="border-b border-base-700 bg-base-800/60">
              <tr><th className="th">Finding</th><th className="th">Case</th><th className="th">Severity</th>
                <th className="th">Confidence</th><th className="th">Classification</th>
                <th className="th">Evidence</th><th className="th">Events</th><th className="th">Generated</th></tr>
            </thead>
            <tbody>
              {items.length === 0 && <tr><td className="td text-slate-500" colSpan={8}>No findings found.</td></tr>}
              {items.map((f) => (
                <tr key={f.id} className="cursor-pointer border-b border-base-800 hover:bg-base-800" onClick={() => setOpen(f)}>
                  <td className="td">
                    <span className="font-mono text-xs text-rose-300">{f.code}</span>
                    <div className="max-w-72 truncate">{f.title}</div>
                  </td>
                  <td className="td">
                    {f.investigation_code && (
                      <Link to={`/cases/${f.investigation_id}/findings`} onClick={(e) => e.stopPropagation()}
                        className="font-mono text-xs text-cyan-300 hover:underline">{f.investigation_code}</Link>
                    )}
                  </td>
                  <td className="td"><SeverityBadge value={f.severity} /></td>
                  <td className="td"><ConfidenceBadge value={f.confidence} /></td>
                  <td className="td"><ClassificationBadge value={f.classification} /></td>
                  <td className="td text-xs">{f.supporting_evidence_ids.length}</td>
                  <td className="td text-xs">{f.supporting_event_ids.length}</td>
                  <td className="td text-xs text-slate-500">{fmtTime(f.generated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {open && <FindingDetailModal finding={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

/* ----------------------------------------------------------------- Integrity */
export function GlobalIntegrity() {
  const [cases, setCases] = useState<Investigation[] | null>(null);
  const [results, setResults] = useState<Record<number, IntegrityResult>>({});
  const [busyId, setBusyId] = useState<number | null>(null);

  useEffect(() => {
    api.get<{ items: Investigation[] }>("/investigations").then((r) => setCases(r.items)).catch(() => setCases([]));
  }, []);

  const verify = async (inv: Investigation) => {
    setBusyId(inv.id);
    try {
      const r = await api.post<IntegrityResult>(`/investigations/${inv.id}/integrity/verify`);
      setResults((prev) => ({ ...prev, [inv.id]: r }));
    } catch { /* toast-less for now */ }
    setBusyId(null);
  };

  const totals = Object.values(results).reduce(
    (acc, r) => ({
      verified: acc.verified + r.verified,
      modified: acc.modified + r.modified,
      missing: acc.missing + r.missing,
    }),
    { verified: 0, modified: 0, missing: 0 },
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-100">Evidence Integrity</h1>
        <Lock size={18} className="text-slate-500" />
      </div>
      <p className="text-sm text-slate-500">
        Verifying recalculates each file's SHA-256 and re-checks the hash-chain ledger. Hashes prove
        stored bytes match their recorded fingerprint — not that contents are truthful.
      </p>

      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Verified (all cases)" value={totals.verified} icon={<ShieldAlert size={18} />} tone="emerald" />
        <StatCard label="Modified" value={totals.modified} icon={<RefreshCw size={18} />} tone={totals.modified ? "rose" : "cyan"} />
        <StatCard label="Missing" value={totals.missing} icon={<FileText size={18} />} tone={totals.missing ? "orange" : "cyan"} />
      </div>

      {!cases && <Spinner />}
      {cases?.map((inv) => {
        const r = results[inv.id];
        return (
          <div key={inv.id} className="card p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <Link to={`/cases/${inv.id}/integrity`} className="font-mono text-sm text-cyan-300 hover:underline">{inv.code}</Link>
                <span className="ml-2 text-sm text-slate-300">{inv.name}</span>
              </div>
              <button className="btn-ghost" onClick={() => verify(inv)} disabled={busyId === inv.id}>
                <RefreshCw size={13} className={busyId === inv.id ? "animate-spin" : ""} /> Verify
              </button>
            </div>
            {r && (
              <div className="mt-3 space-y-1.5">
                <div className={r.chain_valid ? "text-xs text-emerald-300" : "text-xs text-rose-300"}>
                  Ledger chain {r.chain_valid ? "VALID" : `BROKEN — ${r.chain_error}`}
                </div>
                {r.items.map((it) => (
                  <div key={it.evidence_code} className="flex flex-wrap items-center gap-2 border-b border-base-800 py-1 text-xs">
                    <span className="font-mono text-sky-300">{it.evidence_code}</span>
                    <span className="text-slate-300">{it.filename}</span>
                    <span className="font-mono text-[10px] text-slate-600">
                      stored {shortHash(it.stored_hash, 10)} vs current {it.current_hash ? shortHash(it.current_hash, 10) : "—"}
                    </span>
                    <span className="ml-auto"><IntegrityBadge status={it.status.includes("VIOLATION") ? "violation" : it.status.toLowerCase()} /></span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------- Reports */
export function GlobalReports() {
  const [items, setItems] = useState<Report[] | null>(null);
  const [html, setHtml] = useState<string | null>(null);

  useEffect(() => {
    api.get<{ items: Report[] }>("/reports").then((r) => setItems(r.items)).catch(() => setItems([]));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-slate-100">Reports</h1>
      {!items && <Spinner />}
      {items && items.length === 0 && (
        <div className="card p-8 text-center text-sm text-slate-400">
          No reports yet — open a case and press “Generate Report”.
        </div>
      )}
      {items && items.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-2">
            {items.map((r) => (
              <div key={r.id} className="card p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-cyan-300">{r.code}</span>
                  <Link to={`/cases/${r.investigation_id}/report`} className="font-mono text-[11px] text-slate-400 hover:underline">
                    {r.investigation_code}
                  </Link>
                </div>
                <div className="mt-0.5 text-xs text-slate-500">{fmtTime(r.created_at)} · sha256 {shortHash(r.sha256, 12)}</div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <button className="btn-ghost !py-1 !px-2 text-xs" onClick={() => setHtml(`/api/reports/${r.id}/download?format=html`)}>Preview</button>
                  {r.formats.map((f) => (
                    <a key={f} className="btn-ghost !py-1 !px-2 text-xs" href={`/api/reports/${r.id}/download?format=${f}`}
                      target="_blank" rel="noreferrer"><Download size={12} /> {f.toUpperCase()}</a>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="card overflow-hidden lg:col-span-2">
            {html
              ? <iframe src={html} title="Report" className="h-[75vh] w-full bg-white" />
              : <div className="flex h-64 items-center justify-center text-sm text-slate-500">Preview appears here.</div>}
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ Settings */
export function Settings() {
  const [info, setInfo] = useState<SystemInfo | null>(null);
  useEffect(() => {
    api.get<SystemInfo>("/system/info").then(setInfo).catch(() => {});
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-slate-100">Settings &amp; System</h1>
      {!info && <Spinner />}
      {info && (
        <div className="grid gap-4 md:grid-cols-2">
          <div className="card p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-200"><Cpu size={15} /> AI Analysis Engine</div>
            <KV label="Provider">{info.ai_provider}</KV>
            <KV label="Mode">
              <span className={info.ai_provider_mode === "external" ? "text-amber-300" : "text-emerald-300"}>
                {info.ai_provider_mode}
              </span>
            </KV>
            <div className="mt-2 rounded border border-base-700 bg-base-900 p-2 text-xs text-slate-400">
              {info.privacy_note}
            </div>
            <div className="mt-2 text-[11px] text-slate-500">
              To enable an external LLM, set <code className="font-mono text-cyan-300">AI_PROVIDER=openai</code> and
              <code className="font-mono text-cyan-300"> OPENAI_API_KEY</code> in the backend environment, then restart.
              The deterministic engine stays as automatic fallback.
            </div>
          </div>
          <div className="card p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-200"><Server size={15} /> System</div>
            <KV label="App">{info.app} v{info.version}</KV>
            <KV label="Database" mono>{info.database_url}</KV>
            <KV label="Evidence storage" mono>{info.evidence_storage}</KV>
            <KV label="Report storage" mono>{info.report_storage}</KV>
            <KV label="Max upload">{info.max_upload_mb} MB</KV>
          </div>
          <div className="card p-4 md:col-span-2">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-200"><HardDrive size={15} /> Security posture</div>
            <ul className="list-disc space-y-1 pl-4 text-xs text-slate-400">
              <li>Evidence is hashed with SHA-256 on upload and never modified afterwards.</li>
              <li>Uploaded files are stored under random names — original filenames never touch the filesystem path.</li>
              <li>Executables and scripts are rejected; other unknown types are stored metadata/hash-only.</li>
              <li>Evidence is treated as untrusted data: never executed, never parsed as code.</li>
              <li>Every important action is appended to a tamper-evident hash-chain ledger.</li>
              <li>No external AI is contacted unless explicitly configured by the investigator.</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

// Investigation workspace: Overview / Evidence / Timeline / Findings / Traceability / Integrity / Report
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Activity, ChevronDown, ChevronRight, Clock, Download, FileDigit, FileText, GitBranch, Layers,
  Loader2, Play, Plus, RefreshCw, ShieldAlert, ShieldCheck, Trash2, Upload, Zap,
} from "lucide-react";
import { api } from "../services/api";
import {
  ClassificationBadge, ConfidenceBadge, ErrorBox, EventBadge, IntegrityBadge, KV, Modal,
  SeverityBadge, Spinner, StatCard,
} from "../components/ui";
import { EventDetailModal, FindingDetailModal } from "../components/detail";
import { cls, fmtTime, formatBytes, shortHash, timeOnly } from "../utils/format";
import { CASE_STATUSES, type AnalysisRun, type AuditEntry, type Evidence, type EvidencePreview, type Finding, type IntegrityResult, type Investigation, type LedgerRecord, type NormalizedEvent, type Report, type TimelineItem } from "../types";

const TABS = [
  ["overview", "Overview", Activity],
  ["evidence", "Evidence", FileDigit],
  ["timeline", "Timeline", Clock],
  ["findings", "Findings", ShieldAlert],
  ["traceability", "Traceability", GitBranch],
  ["integrity", "Integrity", ShieldCheck],
  ["report", "Report", FileText],
] as const;

export default function CaseDetail() {
  const { id, tab } = useParams();
  const nav = useNavigate();
  const invId = Number(id);
  const activeTab = tab ?? "overview";

  const [inv, setInv] = useState<Investigation | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [eventId, setEventId] = useState<number | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const refreshInv = useCallback(() => {
    api.get<Investigation>(`/investigations/${invId}`).then(setInv).catch((e) => setErr(e.message));
  }, [invId]);

  useEffect(refreshInv, [refreshInv]);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 4000);
    return () => window.clearTimeout(t);
  }, [toast]);

  if (err) return <ErrorBox message={err} />;
  if (!inv) return <Spinner label="Loading investigation" />;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm text-cyan-300">{inv.code}</span>
              <SeverityBadge value={inv.severity} />
              <span className="chip border border-slate-600 bg-slate-600/20 text-slate-300 uppercase">{inv.status}</span>
              <span className="chip border border-slate-600 bg-slate-600/20 text-slate-400">{inv.incident_type}</span>
              <IntegrityBadge status={inv.integrity_status === "Verified" ? "verified" : "violation"} />
            </div>
            <h1 className="mt-1.5 text-lg font-bold text-slate-100">{inv.name}</h1>
            <p className="max-w-3xl text-sm text-slate-500">{inv.description || "No description."}</p>
          </div>
          <div className="flex items-center gap-2">
            <select className="input max-w-36" value={inv.status}
              onChange={async (e) => {
                await api.put(`/investigations/${invId}`, { status: e.target.value });
                refreshInv(); setToast("Status updated");
              }}>
              {CASE_STATUSES.map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-3 border-t border-base-700 pt-3 text-xs text-slate-500">
          <span>Investigator: <span className="text-slate-300">{inv.investigator || "unassigned"}</span></span>
          <span>Created: <span className="text-slate-300">{fmtTime(inv.created_at)}</span></span>
          <span>Updated: <span className="text-slate-300">{fmtTime(inv.updated_at)}</span></span>
        </div>
      </div>

      {/* Quick stats */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4 xl:grid-cols-6">
        <StatCard label="Evidence" value={inv.evidence_count} icon={<FileDigit size={18} />} tone="violet" />
        <StatCard label="Events" value={inv.event_count} icon={<Activity size={18} />} tone="cyan" />
        <StatCard label="Suspicious" value={inv.suspicious_event_count} icon={<Zap size={18} />} tone="amber" />
        <StatCard label="Findings" value={inv.finding_count} icon={<ShieldAlert size={18} />} tone="rose" />
        <StatCard label="Integrity" value={inv.integrity_status === "Verified" ? "OK" : "VIOLATION"} icon={<ShieldCheck size={18} />} tone={inv.integrity_status === "Verified" ? "emerald" : "rose"} />
        <StatCard label="Case Status" value={inv.status} icon={<Layers size={18} />} tone="sky" />
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-1 border-b border-base-700">
        {TABS.map(([key, label, Icon]) => (
          <button key={key}
            onClick={() => nav(`/cases/${invId}/${key}`)}
            className={cls(
              "flex items-center gap-1.5 rounded-t-md px-3.5 py-2 text-sm font-medium",
              activeTab === key
                ? "border-b-2 border-accent bg-base-850 text-cyan-200"
                : "text-slate-400 hover:bg-base-850 hover:text-slate-200",
            )}>
            <Icon size={15} /> {label}
          </button>
        ))}
      </div>

      {activeTab === "overview" && <OverviewTab invId={invId} onOpenEvent={setEventId} />}
      {activeTab === "evidence" && <EvidenceTab invId={invId} onChanged={refreshInv} onToast={setToast} />}
      {activeTab === "timeline" && <TimelineTab invId={invId} onOpenEvent={setEventId} />}
      {activeTab === "findings" && <FindingsTab invId={invId} onOpenFinding={setFinding} onChanged={refreshInv} />}
      {activeTab === "traceability" && <TraceabilityTab invId={invId} onOpenFinding={setFinding} />}
      {activeTab === "integrity" && <IntegrityTab invId={invId} onChanged={refreshInv} onToast={setToast} />}
      {activeTab === "report" && <ReportTab invId={invId} onToast={setToast} />}

      {finding && <FindingDetailModal finding={finding} onClose={() => setFinding(null)} />}
      {eventId !== null && <EventDetailModal eventId={eventId} onClose={() => setEventId(null)} />}

      {toast && (
        <div className="fixed bottom-5 right-5 z-50 rounded-md border border-cyan-500/40 bg-base-850 px-4 py-2.5 text-sm text-cyan-100 shadow-lg">
          {toast}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ Overview */
function OverviewTab({ invId, onOpenEvent }: { invId: number; onOpenEvent: (id: number) => void }) {
  const [run, setRun] = useState<AnalysisRun | null>(null);
  const [missing, setMissing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);

  const load = useCallback(() => {
    api.get<AnalysisRun>(`/investigations/${invId}/analysis`).then((r) => { setRun(r); setMissing(false); })
      .catch((e) => { if (e.status === 404) setMissing(true); else setErr(e.message); });
    api.get<{ items: AuditEntry[] }>(`/investigations/${invId}/audit`).then((r) => setAudit(r.items)).catch(() => {});
  }, [invId]);
  useEffect(load, [load]);

  const analyze = async () => {
    setBusy(true); setErr(null);
    try {
      await api.post(`/investigations/${invId}/analyze`);
      load();
    } catch (e: any) { setErr(e.message); }
    setBusy(false);
  };

  const s = run?.summary;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm text-slate-400">
          {run
            ? <>Last analysis <span className="font-mono text-xs text-slate-300">{run.code}</span> · engine: <span className="text-cyan-300">{run.engine}</span> · {fmtTime(run.finished_at)}</>
            : "No analysis run yet."}
        </div>
        <button className="btn-primary" onClick={analyze} disabled={busy}>
          {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
          {busy ? "Analyzing…" : "Run Analysis"}
        </button>
      </div>
      {err && <ErrorBox message={err} />}

      {missing && !busy && (
        <div className="card p-6 text-center text-sm text-slate-400">
          Upload evidence in the <b className="text-slate-200">Evidence</b> tab, then run the analysis to
          detect suspicious events, correlate them and generate traceable findings.
        </div>
      )}

      {!run && !missing && <Spinner label="Loading analysis" />}

      {s && (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-4 lg:col-span-2">
            <div className="card p-4">
              <div className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">Executive Summary</div>
              <p className="text-sm leading-relaxed text-slate-200">{s.executive_summary}</p>
            </div>
            <div className="card p-4">
              <div className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">What Happened</div>
              <p className="text-sm leading-relaxed text-slate-300">{s.what_happened}</p>
            </div>

            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Attack Stages <span className="normal-case text-slate-500">(only where evidence exists)</span></div>
              {s.attack_stages.length === 0 && <div className="text-sm text-slate-500">No stages supported by evidence.</div>}
              <div className="space-y-2">
                {s.attack_stages.map((st) => (
                  <div key={st.stage} className="rounded-md border border-base-700 p-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium text-fuchsia-300">{st.stage}</span>
                      <ConfidenceBadge value={st.confidence} />
                      <span className="text-xs text-slate-500">{st.event_count} event(s)</span>
                    </div>
                    <div className="mt-0.5 text-xs text-slate-400">{st.summary}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Correlation Chains</div>
              <p className="mb-2 text-[11px] text-slate-500">{s.correlation.note}</p>
              {s.correlation.chains.length === 0 && <div className="text-sm text-slate-500">No correlated sequences detected.</div>}
              <div className="space-y-3">
                {s.correlation.chains.slice(0, 4).map((c) => (
                  <div key={c.chain_id} className="rounded-md border border-base-700 p-3">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-mono text-cyan-300">{c.chain_id}</span>
                      <span className="text-slate-400">{c.suspicious_count} suspicious / {c.event_count} total</span>
                      <span className="text-slate-500">{c.time_span.start ?? "?"} → {c.time_span.end ?? "?"}</span>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {Object.entries(c.shared_attributes).map(([k, vals]) => (
                        <span key={k} className="chip border border-slate-600 bg-slate-600/20 text-slate-400">
                          {k}: {vals.join(", ")}
                        </span>
                      ))}
                    </div>
                    <div className="mt-2 space-y-1 border-l-2 border-base-600 pl-3">
                      {c.sequence.slice(0, 10).map((step) => (
                        <button key={step.event_code} className="block w-full text-left text-xs hover:text-cyan-200"
                          onClick={() => {
                            api.get<{ items: NormalizedEvent[] }>(`/investigations/${invId}/events?suspicious_only=true`)
                              .then((r) => {
                                const ev = r.items.find((x) => x.code === step.event_code);
                                if (ev) onOpenEvent(ev.id);
                              });
                          }}>
                          <span className="font-mono text-slate-500">{timeOnly(step.timestamp)}</span>{" "}
                          <span className="font-mono text-violet-300">{step.event_code}</span>{" "}
                          <EventBadge type={step.event_type} />{" "}
                          <span className="text-slate-400">{step.summary.slice(0, 90)}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-emerald-300">Confirmed by Evidence</div>
              {s.confirmed.length === 0 ? <div className="text-sm text-slate-500">—</div> :
                <ul className="list-disc space-y-1.5 pl-4 text-xs text-slate-300">{s.confirmed.map((c, i) => <li key={i}>{c}</li>)}</ul>}
            </div>
            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-amber-300">Suspected / Inferred</div>
              {s.suspected.length === 0 ? <div className="text-sm text-slate-500">—</div> :
                <ul className="list-disc space-y-1.5 pl-4 text-xs text-slate-300">{s.suspected.map((c, i) => <li key={i}>{c}</li>)}</ul>}
            </div>
            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Missing Information</div>
              <ul className="list-disc space-y-1.5 pl-4 text-xs text-slate-400">{s.missing_information.map((c, i) => <li key={i}>{c}</li>)}</ul>
            </div>
            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-cyan-300">Investigator Next Steps</div>
              <ul className="list-disc space-y-1.5 pl-4 text-xs text-slate-300">{s.next_steps.map((c, i) => <li key={i}>{c}</li>)}</ul>
            </div>
            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Affected Users / Systems</div>
              <div className="flex flex-wrap gap-1">
                {[...s.affected_users.map((u) => `👤 ${u}`), ...s.affected_systems.map((h) => `🖥 ${h}`)].map((x) => (
                  <span key={x} className="chip border border-slate-600 bg-slate-600/20 text-slate-300">{x}</span>
                ))}
                {s.affected_users.length === 0 && s.affected_systems.length === 0 && <span className="text-sm text-slate-500">—</span>}
              </div>
            </div>
            <div className="card p-4">
              <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Audit Trail</div>
              <div className="max-h-64 space-y-1 overflow-y-auto pr-1">
                {audit.map((a) => (
                  <div key={a.id} className="text-[11px] text-slate-400">
                    <span className="text-slate-500">{fmtTime(a.timestamp)}</span>{" "}
                    <span className="text-slate-300">{a.action}</span>{" "}
                    {a.object_id && <span className="font-mono text-cyan-400">{a.object_id}</span>}
                  </div>
                ))}
                {audit.length === 0 && <div className="text-sm text-slate-500">—</div>}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ Evidence */
function EvidenceTab({ invId, onChanged, onToast }: { invId: number; onChanged: () => void; onToast: (m: string) => void }) {
  const [items, setItems] = useState<Evidence[] | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [preview, setPreview] = useState<EvidencePreview | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    api.get<{ items: Evidence[] }>(`/investigations/${invId}/evidence`).then((r) => setItems(r.items)).catch(() => setItems([]));
  }, [invId]);
  useEffect(load, [load]);

  const doUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setUploading(true); setUploadErr(null);
    for (const file of Array.from(files)) {
      try {
        await api.upload(`/investigations/${invId}/evidence`, file, "manual upload", "");
        onToast(`${file.name} uploaded, hashed & parsed`);
      } catch (e: any) {
        setUploadErr(`${file.name}: ${e.message}`);
      }
    }
    setUploading(false);
    load(); onChanged();
    if (fileRef.current) fileRef.current.value = "";
  };

  const remove = async (ev: Evidence) => {
    if (!window.confirm(`Delete evidence ${ev.code} (${ev.original_filename})? The file and its events will be removed; the ledger keeps the fingerprint history.`)) return;
    await api.del(`/evidence/${ev.id}`);
    onToast(`Evidence ${ev.code} deleted`);
    load(); onChanged();
  };

  const showPreview = async (ev: Evidence) => {
    const p = await api.get<EvidencePreview>(`/evidence/${ev.id}/preview`);
    setPreview({ ...p, preview: p.preview });
  };

  return (
    <div className="space-y-4">
      <div
        className="card flex flex-col items-center justify-center gap-2 border-dashed border-base-600 p-8 text-center"
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); doUpload(e.dataTransfer.files); }}>
        <Upload size={22} className="text-slate-500" />
        <div className="text-sm text-slate-300">Drag &amp; drop evidence files here, or</div>
        <button className="btn-primary" onClick={() => fileRef.current?.click()} disabled={uploading}>
          {uploading ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Select Files
        </button>
        <input ref={fileRef} type="file" multiple hidden
          onChange={(e) => doUpload(e.target.files)} />
        <div className="text-[11px] text-slate-500">
          TXT · CSV · JSON · LOG · EML are parsed · PDF/PNG/JPG/PCAP stored with hash + metadata · executables rejected
        </div>
        {uploadErr && <div className="text-xs text-rose-300">{uploadErr}</div>}
      </div>

      {!items && <Spinner label="Loading evidence" />}
      {items && (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[860px]">
            <thead className="border-b border-base-700 bg-base-800/60">
              <tr>
                <th className="th">Evidence</th><th className="th">Type</th><th className="th">Size</th>
                <th className="th">SHA-256</th><th className="th">Events</th><th className="th">Status</th>
                <th className="th">Integrity</th><th className="th">Uploaded</th><th className="th"></th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && <tr><td className="td text-slate-500" colSpan={9}>No evidence uploaded yet.</td></tr>}
              {items.map((ev) => (
                <tr key={ev.id} className="border-b border-base-800 hover:bg-base-800">
                  <td className="td">
                    <button className="font-mono text-xs text-sky-300 hover:underline" onClick={() => showPreview(ev)}>{ev.code}</button>
                    <div className="max-w-56 truncate">{ev.original_filename}</div>
                  </td>
                  <td className="td text-xs uppercase">{ev.file_type}</td>
                  <td className="td text-xs">{formatBytes(ev.size)}</td>
                  <td className="td font-mono text-[11px] text-slate-500" title={ev.sha256}>{shortHash(ev.sha256, 16)}</td>
                  <td className="td">{ev.event_count}</td>
                  <td className="td text-xs">{ev.status}</td>
                  <td className="td"><IntegrityBadge status={ev.integrity_status} /></td>
                  <td className="td text-xs text-slate-500">{fmtTime(ev.uploaded_at)}</td>
                  <td className="td">
                    <div className="flex gap-1">
                      <button title="View evidence" className="rounded p-1 text-slate-400 hover:bg-base-700 hover:text-sky-300" onClick={() => showPreview(ev)}>
                        <FileDigit size={15} />
                      </button>
                      <button title="Delete" className="rounded p-1 text-slate-400 hover:bg-base-700 hover:text-rose-300" onClick={() => remove(ev)}>
                        <Trash2 size={15} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {preview && <EvidencePreviewModal evCode={preview.evidence_code} p={preview} onClose={() => setPreview(null)} />}
    </div>
  );
}

function EvidencePreviewModal({ evCode, p, onClose }: { evCode: string; p: EvidencePreview; onClose: () => void }) {
  const isImage = p.content_type.startsWith("image/");
  return (
    <Modal wide title={<span className="font-mono text-sm">{evCode} · {p.original_filename}</span>} onClose={onClose}>
      <div className="space-y-3">
        <KV label="SHA-256" mono>{p.sha256}</KV>
        <KV label="Size">{formatBytes(p.size)}</KV>
        <KV label="Integrity"><IntegrityBadge status={p.integrity_status} /></KV>
        {Object.keys(p.parse_summary).length > 0 && (
          <div>
            <div className="mb-1 text-xs uppercase tracking-wider text-slate-400">Parse summary</div>
            <pre className="max-h-40 overflow-auto rounded bg-base-950 p-2 font-mono text-[11px] text-slate-300">
              {JSON.stringify(p.parse_summary, null, 2)}
            </pre>
          </div>
        )}
        {isImage ? (
          <div className="max-h-[60vh] overflow-hidden rounded border border-base-700 bg-black">
            <img src={p.preview ?? ""} alt={p.original_filename} className="max-h-[60vh] object-contain" />
          </div>
        ) : p.preview ? (
          <div>
            <div className="mb-1 text-xs uppercase tracking-wider text-slate-400">
              Content preview {p.preview_truncated && <span className="text-amber-400">(truncated)</span>}
            </div>
            <pre className="max-h-[50vh] overflow-auto rounded bg-base-950 p-3 font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap break-all">
              {p.preview}
            </pre>
          </div>
        ) : (
          <div className="rounded border border-base-700 p-3 text-sm text-slate-500">No text preview available for this file type.</div>
        )}
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ Timeline */
function TimelineTab({ invId, onOpenEvent }: { invId: number; onOpenEvent: (id: number) => void }) {
  const [items, setItems] = useState<TimelineItem[] | null>(null);
  useEffect(() => {
    api.get<{ items: TimelineItem[] }>(`/investigations/${invId}/timeline`).then((r) => setItems(r.items)).catch(() => setItems([]));
  }, [invId]);

  if (!items) return <Spinner label="Loading timeline" />;
  if (items.length === 0)
    return <div className="card p-8 text-center text-sm text-slate-400">No timeline yet — run the analysis to build it from suspicious events.</div>;

  return (
    <div className="card p-5">
      <div className="mb-4 flex items-center justify-between">
        <div className="text-sm font-semibold uppercase tracking-wider text-slate-400">Attack Timeline</div>
        <div className="text-xs text-slate-500">
          {items.length} suspicious events · {items[0]?.timestamp?.slice(11, 19) ?? "?"} → {items[items.length - 1]?.timestamp?.slice(11, 19) ?? "?"}
        </div>
      </div>
      <div className="relative space-y-0 border-l-2 border-base-600 pl-0">
        {items.map((t, i) => (
          <button key={t.event_id} onClick={() => onOpenEvent(t.event_id)}
            className="group relative block w-full py-2.5 pl-6 pr-3 text-left hover:bg-base-800/60 rounded-r-md">
            <span className={cls(
              "absolute -left-[7px] top-4 h-3 w-3 rounded-full border-2 border-base-850",
              t.severity === "Critical" || t.severity === "High" ? "bg-rose-500"
                : t.severity === "Medium" ? "bg-amber-400" : "bg-sky-400",
            )} />
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-cyan-300">{timeOnly(t.timestamp)}</span>
              <span className="font-mono text-[11px] text-slate-500">{t.event_code}</span>
              <EventBadge type={t.event_type} />
              {t.severity && <SeverityBadge value={t.severity} />}
              {t.attack_stage && (
                <span className="chip border border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300">{t.attack_stage}</span>
              )}
              <span className="ml-auto font-mono text-[10px] text-slate-500">{t.evidence_code}</span>
            </div>
            <div className="mt-0.5 text-xs text-slate-400 group-hover:text-slate-300">{t.narrative}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ Findings */
function FindingsTab({ invId, onOpenFinding, onChanged }: { invId: number; onOpenFinding: (f: Finding) => void; onChanged: () => void }) {
  const [items, setItems] = useState<Finding[] | null>(null);
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");

  const load = useCallback(() => {
    const qs = new URLSearchParams();
    if (severity) qs.set("severity", severity);
    if (confidence) qs.set("confidence", confidence);
    api.get<{ items: Finding[] }>(`/investigations/${invId}/findings?${qs}`).then((r) => setItems(r.items)).catch(() => setItems([]));
  }, [invId, severity, confidence]);
  useEffect(load, [load]);

  const markReviewed = async (f: Finding) => {
    await api.put(`/findings/${f.id}/status`, { status: f.status === "Reviewed" ? "New" : "Reviewed" });
    load(); onChanged();
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <select className="input max-w-40" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>{["Low", "Medium", "High", "Critical"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <select className="input max-w-40" value={confidence} onChange={(e) => setConfidence(e.target.value)}>
          <option value="">All confidence</option>{["Low", "Medium", "High"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>

      {!items && <Spinner label="Loading findings" />}
      {items && items.length === 0 && (
        <div className="card p-8 text-center text-sm text-slate-400">No findings match — run the analysis first.</div>
      )}
      <div className="grid gap-4 lg:grid-cols-2">
        {items?.map((f) => (
          <div key={f.id} className="card p-4 transition-colors hover:border-base-600">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="font-mono text-xs text-rose-300">{f.code}</div>
                <div className="mt-0.5 font-semibold text-slate-100">{f.title}</div>
              </div>
              {f.status === "Reviewed" && <span className="chip border border-emerald-500/40 bg-emerald-500/10 text-emerald-300">REVIEWED</span>}
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <SeverityBadge value={f.severity} />
              <ConfidenceBadge value={f.confidence} />
              <ClassificationBadge value={f.classification} />
              {f.attack_stage && <span className="chip border border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300">{f.attack_stage}</span>}
            </div>
            <p className="mt-2 line-clamp-3 text-xs leading-relaxed text-slate-400">{f.conclusion}</p>
            <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-base-700 pt-2.5 text-[11px] text-slate-500">
              <span>📄 {f.supporting_evidence_ids.length} evidence</span>
              <span>⚡ {f.supporting_event_ids.length} events</span>
              <span>{f.origin === "ai" ? "AI" : `rule ${f.rule_id}`}</span>
              <div className="ml-auto flex gap-2">
                <button className="text-cyan-300 hover:underline" onClick={() => onOpenFinding(f)}>Trace Finding</button>
                <button className="text-slate-400 hover:underline" onClick={() => markReviewed(f)}>
                  {f.status === "Reviewed" ? "Mark New" : "Mark Reviewed"}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- Traceability */
function TraceabilityTab({ invId, onOpenFinding }: { invId: number; onOpenFinding: (f: Finding) => void }) {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [open, setOpen] = useState<number | null>(null);

  useEffect(() => {
    api.get<{ items: Finding[] }>(`/investigations/${invId}/findings`).then((r) => {
      setFindings(r.items);
      if (r.items.length > 0) setOpen(r.items[0].id);
    }).catch(() => setFindings([]));
    api.get<{ items: Evidence[] }>(`/investigations/${invId}/evidence`).then((r) => setEvidence(r.items));
    api.get<{ items: NormalizedEvent[] }>(`/investigations/${invId}/events?suspicious_only=true`).then((r) => setEvents(r.items));
  }, [invId]);

  const evById = useMemo(() => new Map(evidence.map((e) => [e.code, e])), [evidence]);
  const eventByCode = useMemo(() => new Map(events.map((e) => [e.code, e])), [events]);

  if (!findings) return <Spinner label="Building traceability graph" />;
  if (findings.length === 0)
    return <div className="card p-8 text-center text-sm text-slate-400">Nothing to trace yet — run the analysis first.</div>;

  return (
    <div className="space-y-3">
      <div className="text-sm text-slate-400">
        Every finding expands to its exact events and evidence files. Click any node for details.
      </div>
      {findings.map((f) => (
        <div key={f.id} className="card overflow-hidden">
          <button className="flex w-full items-center gap-2 px-4 py-3 text-left hover:bg-base-800"
            onClick={() => setOpen(open === f.id ? null : f.id)}>
            {open === f.id ? <ChevronDown size={16} className="text-slate-500" /> : <ChevronRight size={16} className="text-slate-500" />}
            <span className="font-mono text-xs text-rose-300">{f.code}</span>
            <span className="font-medium text-slate-100">{f.title}</span>
            <span className="ml-auto flex gap-1.5"><SeverityBadge value={f.severity} /><ConfidenceBadge value={f.confidence} /></span>
          </button>
          {open === f.id && (
            <div className="border-t border-base-700 bg-base-900/50 p-4 text-sm">
              <div className="ml-2 border-l-2 border-rose-500/50 pl-4">
                <div className="py-1 text-xs text-slate-500">FINDING</div>
                <div className="pb-3">
                  <button className="font-semibold text-slate-100 hover:text-cyan-200" onClick={() => onOpenFinding(f)}>
                    {f.title} →
                  </button>
                  <div className="text-xs text-slate-400">{f.conclusion}</div>
                </div>
                <div className="ml-2 border-l-2 border-violet-500/50 pl-4">
                  <div className="py-1 text-xs text-slate-500">EVENTS ({f.supporting_event_ids.length})</div>
                  {f.supporting_event_ids.map((code) => {
                    const ev = eventByCode.get(code);
                    return (
                      <div key={code} className="border-l-2 border-sky-500/50 pl-4">
                        <div className="text-xs">
                          <span className="font-mono text-violet-300">{code}</span>{" "}
                          <span className="text-slate-500">{ev?.timestamp ?? "—"}</span>{" "}
                          {ev && <EventBadge type={ev.event_type} />}
                          <div className="text-slate-400">{(ev?.message ?? "").slice(0, 120)}</div>
                          {ev && (
                            <div className="ml-2 border-l-2 border-sky-700 pl-4 py-1">
                              <div className="text-[11px] text-slate-500">EVIDENCE</div>
                              <span className="font-mono text-sky-300">{ev.evidence_code}</span>{" "}
                              <span className="text-slate-300">
                                {evById.get(ev.evidence_code ?? "")?.original_filename}
                              </span>
                              <div className="font-mono text-[10px] text-slate-600">
                                original file · sha256 {shortHash(evById.get(ev.evidence_code ?? "")?.sha256 ?? "", 20)}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                  {f.supporting_event_ids.length === 0 && <div className="text-xs text-slate-500">—</div>}
                </div>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ----------------------------------------------------------------- Integrity */
function IntegrityTab({ invId, onChanged, onToast }: { invId: number; onChanged: () => void; onToast: (m: string) => void }) {
  const [result, setResult] = useState<IntegrityResult | null>(null);
  const [ledger, setLedger] = useState<LedgerRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [showLedger, setShowLedger] = useState(false);

  const load = useCallback(() => {
    api.get<IntegrityResult>(`/investigations/${invId}/integrity`).then(setResult).catch(() => setResult(null));
    api.get<{ items: LedgerRecord[] }>(`/investigations/${invId}/ledger`).then((r) => setLedger(r.items)).catch(() => {});
  }, [invId]);
  useEffect(load, [load]);

  const verify = async () => {
    setBusy(true);
    try {
      setResult(await api.post<IntegrityResult>(`/investigations/${invId}/integrity/verify`));
      onToast("Integrity verification complete");
      onChanged();
    } catch (e: any) { onToast(`Integrity verification failed: ${e.message}`); }
    setBusy(false);
  };

  if (!result) return <Spinner label="Loading integrity status" />;

  return (
    <div className="space-y-4">
      <div className={cls("card p-4", result.chain_valid ? "border-emerald-500/30" : "border-rose-500/50")}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck size={18} className={result.chain_valid ? "text-emerald-300" : "text-rose-300"} />
              <span className="font-semibold text-slate-100">
                Ledger chain {result.chain_valid ? "VALID" : "BROKEN"}
              </span>
              {result.chain_error && <span className="text-xs text-rose-300">{result.chain_error}</span>}
            </div>
            <div className="mt-1 text-xs text-slate-500">
              Blockchain-style tamper-evident ledger · {result.ledger_length} blocks · hash chaining SHA-256
            </div>
          </div>
          <button className="btn-primary" onClick={verify} disabled={busy}>
            {busy ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />} Verify Integrity
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total Evidence" value={result.total_evidence} icon={<FileDigit size={18} />} tone="violet" />
        <StatCard label="Verified" value={result.verified} icon={<ShieldCheck size={18} />} tone="emerald" />
        <StatCard label="Modified" value={result.modified} icon={<RefreshCw size={18} />} tone={result.modified ? "rose" : "cyan"} />
        <StatCard label="Missing" value={result.missing} icon={<ShieldAlert size={18} />} tone={result.missing ? "orange" : "cyan"} />
      </div>

      <div className="card overflow-x-auto">
        <table className="w-full min-w-[760px]">
          <thead className="border-b border-base-700 bg-base-800/60">
            <tr><th className="th">Evidence</th><th className="th">Stored Hash</th><th className="th">Current Hash</th><th className="th">Status</th></tr>
          </thead>
          <tbody>
            {result.items.length === 0 && <tr><td className="td text-slate-500" colSpan={4}>No evidence.</td></tr>}
            {result.items.map((it) => (
              <tr key={it.evidence_code} className={cls("border-b border-base-800",
                it.status.includes("VIOLATION") && "bg-rose-500/5",
                it.status === "MISSING" && "bg-orange-500/5")}>
                <td className="td">
                  <span className="font-mono text-xs text-sky-300">{it.evidence_code}</span>
                  <div>{it.filename}</div>
                </td>
                <td className="td font-mono text-[11px] text-slate-500">{shortHash(it.stored_hash, 24)}</td>
                <td className="td font-mono text-[11px] text-slate-500">
                  {it.current_hash ? shortHash(it.current_hash, 24) : "—"}
                </td>
                <td className="td">
                  <IntegrityBadge status={it.status.includes("VIOLATION") ? "violation" : it.status.toLowerCase()} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <button className="btn-ghost" onClick={() => setShowLedger(!showLedger)}>
        <GitBranch size={14} /> {showLedger ? "Hide" : "Show"} integrity ledger ({ledger.length} blocks)
      </button>
      {showLedger && (
        <div className="card overflow-x-auto">
          <table className="w-full min-w-[820px]">
            <thead className="border-b border-base-700 bg-base-800/60">
              <tr><th className="th">Block</th><th className="th">Action</th><th className="th">Previous</th><th className="th">Current</th><th className="th">Time</th></tr>
            </thead>
            <tbody>
              {ledger.map((b) => (
                <tr key={b.id} className="border-b border-base-800">
                  <td className="td font-mono text-xs text-cyan-300">{b.code}</td>
                  <td className="td text-xs">{b.action}</td>
                  <td className="td font-mono text-[10px] text-slate-600">{shortHash(b.previous_hash, 14)}</td>
                  <td className="td font-mono text-[10px] text-slate-400">{shortHash(b.current_hash, 14)}</td>
                  <td className="td text-xs text-slate-500">{fmtTime(b.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-[11px] text-slate-500">
        Note: a matching hash proves the stored bytes equal the recorded fingerprint. It does not prove
        the content itself is truthful.
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------- Report */
function ReportTab({ invId, onToast }: { invId: number; onToast: (m: string) => void }) {
  const [reports, setReports] = useState<Report[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api.get<{ items: Report[] }>(`/investigations/${invId}/report`).then((r) => setReports(r.items)).catch(() => setReports([]));
  }, [invId]);
  useEffect(load, [load]);

  const generate = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.post<Report>(`/investigations/${invId}/report`);
      onToast(`Report ${r.code} generated`);
      load();
    } catch (e: any) { setErr(e.message); }
    setBusy(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm text-slate-400">Professional investigation report with executive summary, timeline, findings, traceability and integrity sections.</div>
        <button className="btn-primary" onClick={generate} disabled={busy}>
          {busy ? <Loader2 size={14} className="animate-spin" /> : <FileText size={14} />} Generate Report
        </button>
      </div>
      {err && <ErrorBox message={err} />}

      {!reports && <Spinner label="Loading reports" />}
      {reports && reports.length === 0 && (
        <div className="card p-8 text-center text-sm text-slate-400">No reports generated yet.</div>
      )}
      {reports && reports.length > 0 && (
        <div className="grid gap-4 lg:grid-cols-3">
          <div className="space-y-2 lg:col-span-1">
            {reports.map((r) => (
              <div key={r.id} className="card p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-cyan-300">{r.code}</span>
                  <span className="text-[11px] text-slate-500">{fmtTime(r.created_at)}</span>
                </div>
                <div className="mt-1 text-xs text-slate-500">sha256 {shortHash(r.sha256, 18)}</div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <button className="btn-ghost !py-1 !px-2 text-xs" onClick={() => setPreviewHtml(`/api/reports/${r.id}/download?format=html`)}>Preview</button>
                  {r.formats.map((f) => (
                    <a key={f} href={`/api/reports/${r.id}/download?format=${f}`} target="_blank" rel="noreferrer"
                      className="btn-ghost !py-1 !px-2 text-xs">
                      <Download size={12} /> {f.toUpperCase()}
                    </a>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="card overflow-hidden lg:col-span-2">
            {previewHtml ? (
              <iframe src={previewHtml} title="Report preview" className="h-[75vh] w-full bg-white" />
            ) : (
              <div className="flex h-64 items-center justify-center text-sm text-slate-500">
                Select “Preview” on a report to view it here.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Finding traceability modal + event detail modal (used across pages).
import { useEffect, useState } from "react";
import { FileDigit, Link2 } from "lucide-react";
import { api } from "../services/api";
import { ClassificationBadge, ConfidenceBadge, EventBadge, ErrorBox, KV, Modal, SeverityBadge, Spinner } from "./ui";
import { fmtTime, shortHash } from "../utils/format";
import type { Evidence, Finding, NormalizedEvent } from "../types";

export function FindingDetailModal({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const [tree, setTree] = useState<{ events: NormalizedEvent[]; evidence: Evidence[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.get<{ events: NormalizedEvent[]; evidence: Evidence[] }>(`/findings/${finding.id}/evidence`)
      .then(setTree).catch((e) => setErr(e.message));
  }, [finding.id]);

  return (
    <Modal wide title={<span className="font-mono text-sm text-rose-300">{finding.code}</span>} onClose={onClose}>
      <div className="space-y-4">
        <div>
          <div className="text-lg font-semibold text-slate-100">{finding.title}</div>
          <div className="mt-1.5 flex flex-wrap gap-2">
            <SeverityBadge value={finding.severity} />
            <ConfidenceBadge value={finding.confidence} />
            <ClassificationBadge value={finding.classification} />
            {finding.attack_stage && (
              <span className="chip border border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300">
                STAGE: {finding.attack_stage}
              </span>
            )}
            <span className="chip border border-slate-600 bg-slate-600/20 text-slate-400 uppercase">
              {finding.origin === "ai" ? "AI finding" : `Rule ${finding.rule_id}`}
            </span>
          </div>
        </div>

        <div className="rounded-md border border-base-700 bg-base-900 p-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">Conclusion</div>
          <p className="mt-1 text-sm text-slate-200">{finding.conclusion}</p>
        </div>
        <div className="rounded-md border border-base-700 bg-base-900 p-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Why TRACE-X reached this conclusion (evidence-based explanation)
          </div>
          <p className="mt-1 text-sm text-slate-300">{finding.explanation}</p>
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-md border border-base-700 p-3">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Supporting Evidence</div>
            {finding.supporting_evidence_ids.length === 0 && <div className="text-xs text-slate-500">—</div>}
            {finding.supporting_evidence_ids.map((id) => (
              <div key={id} className="font-mono text-xs text-sky-300">{id}</div>
            ))}
          </div>
          <div className="rounded-md border border-base-700 p-3">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Supporting Events</div>
            {finding.supporting_event_ids.length === 0 && <div className="text-xs text-slate-500">—</div>}
            <div className="flex flex-wrap gap-1">
              {finding.supporting_event_ids.map((id) => (
                <span key={id} className="font-mono text-xs text-violet-300">{id}</span>
              ))}
            </div>
          </div>
        </div>

        {finding.excerpts.length > 0 && (
          <div className="rounded-md border border-base-700 p-3">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Evidence Excerpts</div>
            <div className="space-y-1.5">
              {finding.excerpts.map((ex, i) => (
                <div key={i} className="rounded bg-base-950 p-2 font-mono text-[11px] leading-relaxed text-slate-300">
                  <span className="text-cyan-400">{ex.evidence_code}</span>
                  <span className="text-slate-500"> · {ex.timestamp ?? "no time"} · {ex.event_code}</span>
                  <div className="whitespace-pre-wrap break-all mt-0.5">{ex.text}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div>
          <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
            <Link2 size={13} /> Traceability: Finding → Events → Evidence → Original File
          </div>
          {err && <ErrorBox message={err} />}
          {!tree && !err && <Spinner label="Loading evidence trace" />}
          {tree && (
            <div className="space-y-2">
              {tree.evidence.map((ev) => (
                <div key={ev.id} className="rounded-md border border-base-700 p-3">
                  <div className="flex items-center gap-2">
                    <FileDigit size={14} className="text-sky-300" />
                    <span className="font-mono text-xs text-sky-300">{ev.code}</span>
                    <span className="text-sm text-slate-200">{ev.original_filename}</span>
                    <span className="ml-auto font-mono text-[10px] text-slate-500">{shortHash(ev.sha256, 20)}</span>
                  </div>
                  <div className="mt-1 border-l-2 border-base-600 pl-3 pt-1">
                    {tree.events.filter((e) => e.evidence_id === ev.id).map((e) => (
                      <div key={e.id} className="py-0.5 text-xs">
                        <span className="font-mono text-violet-300">{e.code}</span>
                        <span className="text-slate-500"> {e.timestamp ?? "—"} </span>
                        <EventBadge type={e.event_type} />
                        <span className="ml-2 text-slate-400">{(e.message ?? "").slice(0, 110)}</span>
                      </div>
                    ))}
                    {tree.events.filter((e) => e.evidence_id === ev.id).length === 0 && (
                      <div className="text-xs text-slate-500">Referenced via finding summary.</div>
                    )}
                  </div>
                </div>
              ))}
              {tree.evidence.length === 0 && <div className="text-xs text-slate-500">No evidence links recorded.</div>}
            </div>
          )}
        </div>

        {finding.recommendations.length > 0 && (
          <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 p-3">
            <div className="text-xs font-semibold uppercase tracking-wider text-cyan-300 mb-1.5">Recommended Next Steps</div>
            <ul className="list-disc space-y-1 pl-4 text-sm text-slate-300">
              {finding.recommendations.map((r, i) => <li key={i}>{r}</li>)}
            </ul>
          </div>
        )}
      </div>
    </Modal>
  );
}

export function EventDetailModal({ eventId, onClose }: { eventId: number; onClose: () => void }) {
  const [ev, setEv] = useState<NormalizedEvent | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.get<NormalizedEvent>(`/events/${eventId}`).then(setEv).catch((e) => setErr(e.message));
  }, [eventId]);

  return (
    <Modal title={<span className="font-mono text-sm text-violet-300">{ev?.code ?? "Event"}</span>} onClose={onClose}>
      {err && <ErrorBox message={err} />}
      {!ev && !err && <Spinner label="Loading event" />}
      {ev && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <EventBadge type={ev.event_type} />
            {ev.is_suspicious && (
              <span className="chip border border-amber-500/40 bg-amber-500/10 text-amber-300">SUSPICIOUS</span>
            )}
            {ev.severity && <SeverityBadge value={ev.severity} />}
          </div>
          <div className="rounded-md border border-base-700 bg-base-900 p-2">
            <KV label="Timestamp">{fmtTime(ev.timestamp)}</KV>
            <KV label="Source evidence" mono>{ev.evidence_code}</KV>
            <KV label="Username" mono>{ev.username ?? "—"}</KV>
            <KV label="Source IP" mono>{ev.source_ip ?? "—"}</KV>
            <KV label="Destination IP" mono>{ev.destination_ip ?? "—"}</KV>
            <KV label="Host" mono>{ev.hostname ?? "—"}</KV>
            <KV label="Action / Status">{[ev.action, ev.status].filter(Boolean).join(" / ") || "—"}</KV>
            {ev.file_path && <KV label="File" mono>{ev.file_path}</KV>}
            {ev.byte_count != null && <KV label="Bytes" mono>{ev.byte_count.toLocaleString()}</KV>}
            {ev.url && <KV label="URL" mono>{ev.url}</KV>}
            {ev.domain && <KV label="Domain" mono>{ev.domain}</KV>}
          </div>
          {ev.suspicion_reason && (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-200">
              <span className="font-semibold">Why suspicious: </span>{ev.suspicion_reason}
            </div>
          )}
          {ev.raw_line && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Raw evidence line</div>
              <pre className="overflow-x-auto rounded bg-base-950 p-2 font-mono text-[11px] text-slate-300 whitespace-pre-wrap break-all">
                {ev.raw_line}
              </pre>
            </div>
          )}
          {ev.related_events && ev.related_events.length > 0 && (
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Related suspicious events</div>
              <div className="space-y-1">
                {ev.related_events.map((r) => (
                  <div key={r.code} className="rounded border border-base-700 px-2 py-1 text-xs">
                    <span className="font-mono text-violet-300">{r.code}</span>
                    <span className="text-slate-500"> {r.timestamp ?? "—"} </span>
                    <EventBadge type={r.event_type} />
                    <span className="ml-2 text-slate-400">{r.message.slice(0, 100)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

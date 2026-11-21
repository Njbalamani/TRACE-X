"""The analysis orchestrator. Full pipeline:

mark suspicious -> deterministic detections -> correlation chains ->
attack stages -> AI layer (validated) -> findings + traceability links ->
timeline -> ledger + audit records.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.ai import provider as ai_provider_module
from app.analyzers import detection, stages
from app.integrity.ledger import ledger
from app.models.models import (
    AnalysisRun,
    Event,
    Evidence,
    Finding,
    FindingEvidenceLink,
    Investigation,
    TimelineEvent,
)
from app.services import correlation_service
from app.services.audit_service import log_action
from app.services.timeline_service import rebuild_timeline

SEVERITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}


def run_analysis(db: Session, investigation: Investigation) -> AnalysisRun:
    run = AnalysisRun(investigation_id=investigation.id, status="Running",
                      engine=ai_provider_module.provider_mode())
    db.add(run)
    db.flush()

    try:
        events = list(db.scalars(select(Event).where(Event.investigation_id == investigation.id)))
        if not events:
            raise ValueError("Insufficient evidence to generate a confident conclusion: "
                             "no normalized events are available. Upload parseable evidence first.")

        # ---- 1. suspicion flags (recomputed fresh every run) ----------------
        for e in events:
            e.is_suspicious = False
            e.suspicion_reason = None
            e.severity = None

        detections = detection.run_detections(events)
        for d in detections:
            for e in d.get("events", []):
                if not e.is_suspicious or (e.severity and
                        SEVERITY_RANK.get(d["severity"], 0) > SEVERITY_RANK.get(e.severity, 0)):
                    e.is_suspicious = True
                e.severity = d["severity"] if (not e.severity or
                        SEVERITY_RANK.get(d["severity"], 0) > SEVERITY_RANK.get(e.severity, 0)) else e.severity
                note = f"{d['title']} ({d['classification']})"
                e.suspicion_reason = note if not e.suspicion_reason else f"{e.suspicion_reason}; {note}"
        db.flush()

        suspicious_events = [e for e in events if e.is_suspicious]

        # ---- 2. correlation + stages ----------------------------------------
        correlation = correlation_service.build_correlation(events)
        chains = correlation["chains"]
        stage_list = stages.build_stages(events)

        # ---- 3. AI layer (deterministic by default; optional external LLM) --
        provider = ai_provider_module.get_provider()
        try:
            ai_result = provider.analyze(investigation, events, detections, chains, stage_list)
            ai_error = None
        except Exception as exc:
            # external AI failing must never break the deterministic pipeline
            fallback = ai_provider_module.DeterministicProvider()
            ai_result = fallback.analyze(investigation, events, detections, chains, stage_list)
            ai_error = f"External AI unavailable — deterministic analysis used. ({exc.__class__.__name__})"

        # ---- 4. persist findings -------------------------------------------
        db.execute(delete(FindingEvidenceLink).where(FindingEvidenceLink.finding_id.in_(
            select(Finding.id).where(Finding.investigation_id == investigation.id))))
        db.execute(delete(Finding).where(Finding.investigation_id == investigation.id))
        db.flush()

        for d in detections:
            if not d.get("events"):
                continue
            finding = Finding(
                investigation_id=investigation.id,
                analysis_run_id=run.id,
                title=d["title"], severity=d["severity"], confidence=d["confidence"],
                classification=d["classification"], attack_stage=d.get("attack_stage"),
                conclusion=d["conclusion"], explanation=d["explanation"],
                supporting_evidence_ids=d["evidence_ids"],
                supporting_event_ids=d["event_ids"],
                timestamps_involved=d["timestamps"],
                excerpts=d["excerpts"],
                recommendations=d.get("recommendations") or [],
                origin="detection_rule", rule_id=d["rule_id"],
            )
            db.add(finding)
            db.flush()
            _persist_links(db, finding, d["events"])

        # AI-added findings (only from external provider; deterministic ones are
        # already covered by the rule findings above)
        if getattr(provider, "name", "") == "openai":
            for af in ai_result.findings:
                event_rows = [e for e in events if e.code in set(af.supporting_event_ids)]
                finding = Finding(
                    investigation_id=investigation.id,
                    analysis_run_id=run.id,
                    title=af.title, severity=af.severity, confidence=af.confidence,
                    classification=af.classification, attack_stage=af.attack_stage,
                    conclusion=af.conclusion, explanation=af.explanation,
                    supporting_evidence_ids=af.supporting_evidence_ids,
                    supporting_event_ids=af.supporting_event_ids,
                    timestamps_involved=sorted({e.timestamp for e in event_rows if e.timestamp}),
                    excerpts=[{"event_code": e.code,
                               "evidence_code": e.evidence.code if e.evidence else None,
                               "timestamp": e.timestamp,
                               "text": (e.raw_line or e.message or "")[:300]}
                              for e in event_rows[:6]],
                    recommendations=af.recommendations,
                    origin="ai",
                )
                db.add(finding)
                db.flush()
                _persist_links(db, finding, event_rows)

        # ---- 5. timeline ------------------------------------------------------
        rebuild_timeline(db, investigation.id, suspicious_events, stage_list)

        # ---- 6. run summary ---------------------------------------------------
        run.status = "Completed"
        run.finished_at = datetime.now(timezone.utc)
        run.error = ai_error
        run.summary = {
            "engine": ai_result and provider.name,
            "executive_summary": ai_result.executive_summary,
            "what_happened": ai_result.what_happened,
            "suspicious_activities": ai_result.suspicious_activities,
            "affected_systems": ai_result.affected_systems,
            "affected_users": ai_result.affected_users,
            "confirmed": ai_result.confirmed,
            "suspected": ai_result.suspected,
            "missing_information": ai_result.missing_information,
            "next_steps": ai_result.next_steps,
            "correlation": correlation,
            "attack_stages": stage_list,
            "counts": {
                "events": len(events),
                "suspicious_events": len(suspicious_events),
                "findings": len(detections) + (len(ai_result.findings) if getattr(provider, "name", "") == "openai" else 0),
                "chains": len(chains),
                "stages": len(stage_list),
            },
            "timeline_span": {
                "start": next((e.timestamp for e in suspicious_events if e.timestamp), None),
                "end": next((e.timestamp for e in reversed(suspicious_events) if e.timestamp), None),
            },
        }

        ledger.add_record(db, action="analysis_completed", investigation_id=investigation.id,
                          payload={"run": run.code, "engine": run.engine,
                                   "findings": run.summary["counts"]["findings"],
                                   "suspicious_events": len(suspicious_events)})
        log_action(db, action="evidence_analyzed", investigation_id=investigation.id,
                   object_id=run.code, details={"engine": run.engine})
        db.commit()
        db.refresh(run)
        return run

    except Exception as exc:
        db.rollback()
        run.status = "Failed"
        run.error = str(exc)[:2000]
        run.finished_at = datetime.now(timezone.utc)
        db.add(run)
        db.commit()
        raise


def _persist_links(db: Session, finding: Finding, events: list[Event]) -> None:
    seen = set()
    for e in events:
        key = (e.id, e.evidence_id)
        if key in seen:
            continue
        seen.add(key)
        db.add(FindingEvidenceLink(
            finding_id=finding.id, event_id=e.id, evidence_id=e.evidence_id,
            note=f"{e.code} @ {e.timestamp or 'no timestamp'}",
        ))

"""Investigation + evidence + analysis + integrity + report routes."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.integrity.ledger import ledger
from app.integrity.verify import verify_investigation_integrity
from app.models.models import (
    AnalysisRun,
    Event,
    Evidence,
    Finding,
    Investigation,
    Report,
)
from app.schemas.schemas import (
    AnalysisRunOut,
    EventOut,
    EvidenceOut,
    FindingOut,
    InvestigationCreate,
    InvestigationOut,
    InvestigationUpdate,
    LedgerOut,
    ReportOut,
)
from app.services import investigation_service, report_service, storage
from app.services.analysis_service import run_analysis
from app.services.audit_service import log_action
from app.services.evidence_service import upload_evidence

router = APIRouter()


def _inv(db: Session, investigation_id: int) -> Investigation:
    return investigation_service.get_investigation(db, investigation_id)


def _evidence_out(db: Session, ev: Evidence) -> dict:
    data = EvidenceOut.model_validate(ev).model_dump()
    inv = db.get(Investigation, ev.investigation_id)
    data["investigation_code"] = inv.code if inv else None
    return data


# ---------------------------------------------------------------- investigations
@router.post("/investigations", response_model=InvestigationOut, status_code=201)
def create_investigation(payload: InvestigationCreate, db: Session = Depends(get_db)):
    inv = investigation_service.create_investigation(db, payload)
    return investigation_service.investigation_out(db, inv)


@router.get("/investigations")
def list_investigations(
    db: Session = Depends(get_db),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    incident_type: str | None = Query(None),
    q: str | None = Query(None),
):
    stmt = select(Investigation).order_by(Investigation.updated_at.desc())
    if severity:
        stmt = stmt.where(Investigation.severity == severity)
    if status:
        stmt = stmt.where(Investigation.status == status)
    if incident_type:
        stmt = stmt.where(Investigation.incident_type == incident_type)
    if q:
        stmt = stmt.where(Investigation.name.ilike(f"%{q}%"))
    invs = db.scalars(stmt).all()
    return {"total": len(invs), "items": [
        investigation_service.investigation_out(db, inv) for inv in invs]}


@router.get("/investigations/{investigation_id}", response_model=InvestigationOut)
def get_investigation(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    return investigation_service.investigation_out(db, inv)


@router.put("/investigations/{investigation_id}", response_model=InvestigationOut)
def update_investigation(investigation_id: int, payload: InvestigationUpdate,
                         db: Session = Depends(get_db)):
    inv = investigation_service.update_investigation(db, _inv(db, investigation_id), payload)
    return investigation_service.investigation_out(db, inv)


@router.delete("/investigations/{investigation_id}", status_code=200)
def delete_investigation(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    code = inv.code
    investigation_service.delete_investigation(db, inv)
    return {"deleted": code}


@router.get("/dashboard", summary="Dashboard statistics")
def dashboard(db: Session = Depends(get_db)):
    return investigation_service.dashboard_stats(db)


# ---------------------------------------------------------------- evidence
@router.post("/investigations/{investigation_id}/evidence", status_code=201)
async def upload_evidence_route(investigation_id: int, file: UploadFile,
                                source: str = Query(""),
                                description: str = Query(""),
                                db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    evidence = await _await_upload(db, inv, file, source, description)
    return _evidence_out(db, evidence)


async def _await_upload(db, inv, file, source, description):
    return upload_evidence(db, inv, file, source=source, description=description)


@router.get("/investigations/{investigation_id}/evidence")
def list_evidence(investigation_id: int, db: Session = Depends(get_db)):
    _inv(db, investigation_id)
    evs = db.scalars(select(Evidence).where(
        Evidence.investigation_id == investigation_id).order_by(Evidence.id)).all()
    return {"total": len(evs), "items": [_evidence_out(db, ev) for ev in evs]}


@router.get("/evidence")
def list_all_evidence(db: Session = Depends(get_db),
                      file_type: str | None = Query(None),
                      integrity_status: str | None = Query(None),
                      investigation_id: int | None = Query(None)):
    stmt = select(Evidence).order_by(Evidence.id.desc())
    if file_type:
        stmt = stmt.where(Evidence.file_type == file_type.lower())
    if integrity_status:
        stmt = stmt.where(Evidence.integrity_status == integrity_status)
    if investigation_id:
        stmt = stmt.where(Evidence.investigation_id == investigation_id)
    evs = db.scalars(stmt).all()
    return {"total": len(evs), "items": [_evidence_out(db, ev) for ev in evs]}


@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: int, db: Session = Depends(get_db)):
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    out = _evidence_out(db, ev)
    events = db.scalars(select(Event).where(Event.evidence_id == ev.id).order_by(Event.id)).all()
    from app.schemas.schemas import EventOut as EO
    out["events"] = [EO.model_validate(e).model_dump() | {"code": e.code} for e in events[:200]]
    return out


@router.get("/evidence/{evidence_id}/preview")
def preview_evidence(evidence_id: int, db: Session = Depends(get_db)):
    from app.services.evidence_service import evidence_preview
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    return evidence_preview(db, ev)


@router.get("/evidence/{evidence_id}/raw")
def raw_evidence(evidence_id: int, db: Session = Depends(get_db)):
    from app.services.evidence_service import raw_image_response
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    return raw_image_response(ev)


@router.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: int, db: Session = Depends(get_db)):
    ev = db.get(Evidence, evidence_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    # delete the stored file as well; the ledger entry preserves the fingerprint history
    path = storage.EVIDENCE_STORAGE / ev.stored_filename
    if path.is_file():
        path.unlink()
    code, inv_id = ev.code, ev.investigation_id
    db.delete(ev)
    log_action(db, action="evidence_deleted", investigation_id=inv_id, object_id=code)
    db.commit()
    return {"deleted": code}


# ---------------------------------------------------------------- analysis
@router.post("/investigations/{investigation_id}/analyze")
def analyze(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    try:
        run = run_analysis(db, inv)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"run": AnalysisRunOut.model_validate(run).model_dump(),
            "summary": run.summary,
            "message": ("Analysis completed. Findings are linked to their supporting evidence."
                        if run.status == "Completed" else "Analysis failed.")}


@router.get("/investigations/{investigation_id}/analysis")
def get_latest_analysis(investigation_id: int, db: Session = Depends(get_db)):
    _inv(db, investigation_id)
    run = db.scalars(select(AnalysisRun).where(
        AnalysisRun.investigation_id == investigation_id)
        .order_by(AnalysisRun.id.desc())).first()
    if not run:
        raise HTTPException(status_code=404, detail="No analysis has been run for this investigation yet.")
    return AnalysisRunOut.model_validate(run).model_dump()


# ---------------------------------------------------------------- events & timeline
@router.get("/investigations/{investigation_id}/events")
def list_events(investigation_id: int, db: Session = Depends(get_db),
                event_type: str | None = Query(None),
                suspicious_only: bool = Query(False),
                username: str | None = Query(None),
                source_ip: str | None = Query(None),
                evidence_id: int | None = Query(None),
                limit: int = Query(500, le=2000)):
    _inv(db, investigation_id)
    stmt = select(Event).where(Event.investigation_id == investigation_id)
    if event_type:
        stmt = stmt.where(Event.event_type == event_type.upper())
    if suspicious_only:
        stmt = stmt.where(Event.is_suspicious.is_(True))
    if username:
        stmt = stmt.where(Event.username.ilike(f"%{username}%"))
    if source_ip:
        stmt = stmt.where(or_(Event.source_ip.ilike(f"%{source_ip}%"),
                              Event.destination_ip.ilike(f"%{source_ip}%")))
    if evidence_id:
        stmt = stmt.where(Event.evidence_id == evidence_id)
    stmt = stmt.order_by(Event.timestamp, Event.id).limit(limit)
    events = db.scalars(stmt).all()
    out = []
    for e in events:
        data = EventOut.model_validate(e).model_dump()
        data["evidence_code"] = e.evidence.code if e.evidence else None
        out.append(data)
    return {"total": len(out), "items": out}


@router.get("/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")
    data = EventOut.model_validate(event).model_dump()
    data["evidence_code"] = event.evidence.code if event.evidence else None
    # related events: shared username / source_ip, excluding itself
    related = []
    if event.username or event.source_ip:
        from sqlalchemy import or_
        stmt = select(Event).where(Event.investigation_id == event.investigation_id,
                                   Event.id != event.id,
                                   Event.is_suspicious.is_(True)).limit(20)
        conds = []
        if event.username:
            conds.append(Event.username == event.username)
        if event.source_ip:
            conds.append(Event.source_ip == event.source_ip)
        rows = db.scalars(stmt.where(or_(*conds))).all()
        for r in rows[:10]:
            related.append({"code": r.code, "timestamp": r.timestamp, "event_type": r.event_type,
                            "message": (r.message or "")[:160],
                            "evidence_code": r.evidence.code if r.evidence else None})
    data["related_events"] = related
    return data


@router.get("/investigations/{investigation_id}/timeline")
def timeline(investigation_id: int, db: Session = Depends(get_db)):
    from app.services.timeline_service import get_timeline
    _inv(db, investigation_id)
    return {"items": get_timeline(db, investigation_id)}


# ---------------------------------------------------------------- findings
@router.get("/investigations/{investigation_id}/findings")
def list_findings(investigation_id: int, db: Session = Depends(get_db),
                  severity: str | None = Query(None),
                  confidence: str | None = Query(None),
                  status: str | None = Query(None),
                  attack_stage: str | None = Query(None)):
    _inv(db, investigation_id)
    stmt = select(Finding).where(Finding.investigation_id == investigation_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if confidence:
        stmt = stmt.where(Finding.confidence == confidence)
    if status:
        stmt = stmt.where(Finding.status == status)
    if attack_stage:
        stmt = stmt.where(Finding.attack_stage == attack_stage)
    findings = db.scalars(stmt.order_by(Finding.id)).all()
    inv = db.get(Investigation, investigation_id)
    items = []
    for f in findings:
        data = FindingOut.model_validate(f).model_dump()
        data["investigation_code"] = inv.code if inv else None
        items.append(data)
    return {"total": len(items), "items": items}


@router.get("/findings")
def list_all_findings(db: Session = Depends(get_db),
                      severity: str | None = Query(None),
                      confidence: str | None = Query(None),
                      investigation_id: int | None = Query(None),
                      status: str | None = Query(None)):
    stmt = select(Finding).order_by(Finding.id.desc())
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if confidence:
        stmt = stmt.where(Finding.confidence == confidence)
    if status:
        stmt = stmt.where(Finding.status == status)
    if investigation_id:
        stmt = stmt.where(Finding.investigation_id == investigation_id)
    findings = db.scalars(stmt).all()
    inv_by_id = {i.id: i for i in db.scalars(select(Investigation))}
    items = []
    for f in findings:
        data = FindingOut.model_validate(f).model_dump()
        inv = inv_by_id.get(f.investigation_id)
        data["investigation_code"] = inv.code if inv else None
        items.append(data)
    return {"total": len(items), "items": items}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    data = FindingOut.model_validate(finding).model_dump()
    inv = db.get(Investigation, finding.investigation_id)
    data["investigation_code"] = inv.code if inv else None
    return data


@router.get("/findings/{finding_id}/evidence")
def finding_evidence(finding_id: int, db: Session = Depends(get_db)):
    """Full traceability tree: Finding -> Events -> Evidence -> original file."""
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    from app.models.models import FindingEvidenceLink
    links = db.scalars(select(FindingEvidenceLink).where(
        FindingEvidenceLink.finding_id == finding.id)).all()
    events_out, evidence_out, seen_evidence = [], [], {}
    for link in links:
        event = db.get(Event, link.event_id) if link.event_id else None
        evidence = db.get(Evidence, link.evidence_id) if link.evidence_id else None
        if event:
            e = EventOut.model_validate(event).model_dump()
            e["evidence_code"] = event.evidence.code if event.evidence else None
            events_out.append(e)
        if evidence and evidence.id not in seen_evidence:
            seen_evidence[evidence.id] = True
            evidence_out.append(_evidence_out(db, evidence))
    inv = db.get(Investigation, finding.investigation_id)
    return {
        "finding": FindingOut.model_validate(finding).model_dump() | {
            "investigation_code": inv.code if inv else None},
        "events": events_out,
        "evidence": evidence_out,
    }


@router.put("/findings/{finding_id}/status")
def set_finding_status(finding_id: int, payload: dict, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    status = str(payload.get("status", ""))
    if status not in ("New", "Reviewed"):
        raise HTTPException(status_code=422, detail="Status must be New or Reviewed.")
    finding.status = status
    log_action(db, action="finding_reviewed", investigation_id=finding.investigation_id,
               object_id=finding.code, details={"status": status})
    db.commit()
    return {"code": finding.code, "status": finding.status}


# ---------------------------------------------------------------- integrity
@router.get("/investigations/{investigation_id}/integrity")
def integrity_status(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    evidences = db.scalars(select(Evidence).where(
        Evidence.investigation_id == investigation_id)).all()
    chain = ledger.verify_chain(db, investigation_id=inv.id)
    verified = sum(1 for e in evidences if e.integrity_status == "Verified")
    modified = sum(1 for e in evidences if e.integrity_status == "Violation")
    missing = sum(1 for e in evidences if e.integrity_status == "Missing")
    return {
        "investigation_code": inv.code,
        "chain_valid": chain["valid"], "chain_error": chain.get("error"),
        "total_evidence": len(evidences), "verified": verified,
        "modified": modified, "missing": missing,
        "integrity_violations": modified + missing,
        "ledger_length": chain["blocks_checked"],
        "items": [{
            "evidence_code": e.code, "filename": e.original_filename,
            "stored_hash": e.sha256, "current_hash": None,
            "status": e.integrity_status.upper().replace("VIOLATION", "INTEGRITY VIOLATION"),
            "last_verified_at": e.last_verified_at,
        } for e in evidences],
    }


@router.post("/investigations/{investigation_id}/integrity/verify")
def integrity_verify(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    result = verify_investigation_integrity(db, inv)
    log_action(db, action="integrity_verified", investigation_id=inv.id,
               object_id=inv.code,
               details={"violations": result["integrity_violations"]})
    return result


@router.get("/investigations/{investigation_id}/ledger")
def ledger_records(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    records = ledger.get_records(db, investigation_id=inv.id)
    return {"total": len(records), "items": [
        LedgerOut.model_validate(r).model_dump() for r in records]}


# ---------------------------------------------------------------- reports
@router.post("/investigations/{investigation_id}/report", response_model=ReportOut, status_code=201)
def generate_report(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    report = report_service.generate_report(db, inv)
    out = ReportOut.model_validate(report).model_dump()
    out["investigation_code"] = inv.code
    return out


@router.get("/investigations/{investigation_id}/report")
def latest_report(investigation_id: int, db: Session = Depends(get_db)):
    inv = _inv(db, investigation_id)
    reports = db.scalars(select(Report).where(
        Report.investigation_id == inv.id).order_by(Report.id.desc())).all()
    return {"total": len(reports), "items": [
        ReportOut.model_validate(r).model_dump() | {"investigation_code": inv.code}
        for r in reports]}


@router.get("/reports")
def all_reports(db: Session = Depends(get_db)):
    reports = db.scalars(select(Report).order_by(Report.id.desc())).all()
    inv_by_id = {i.id: i for i in db.scalars(select(Investigation))}
    items = []
    for r in reports:
        out = ReportOut.model_validate(r).model_dump()
        inv = inv_by_id.get(r.investigation_id)
        out["investigation_code"] = inv.code if inv else None
        items.append(out)
    return {"total": len(items), "items": items}


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, format: str = "html", db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    paths = {"md": report.md_path, "html": report.html_path, "pdf": report.pdf_path}
    path_str = paths.get(format) or ""
    if not path_str:
        raise HTTPException(status_code=404,
                            detail=f"Report was not generated in '{format}' format. Available: {report.formats}")
    try:
        path = storage.safe_report_path(os.path.basename(path_str))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report path.")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Report file missing from storage.")
    media = {"md": "text/markdown", "html": "text/html", "pdf": "application/pdf"}[format]
    filename = path.name
    if format == "html":
        return HTMLResponse(content=path.read_text("utf-8"), headers={
            "Content-Disposition": f'inline; filename="{filename}"'})
    return FileResponse(path, media_type=media, filename=filename)


# ---------------------------------------------------------------- audit
@router.get("/investigations/{investigation_id}/audit")
def audit_log(investigation_id: int, db: Session = Depends(get_db)):
    from app.models.models import AuditLog
    _inv(db, investigation_id)
    from sqlalchemy import desc
    rows = db.scalars(select(AuditLog).where(
        AuditLog.investigation_id == investigation_id).order_by(desc(AuditLog.id)).limit(100)).all()
    return {"total": len(rows), "items": [{
        "id": r.id, "timestamp": r.timestamp, "actor": r.actor, "action": r.action,
        "object_id": r.object_id, "details": r.details,
    } for r in rows]}


# search + system live in separate routers
from app.api.search import router as search_router  # noqa: E402
from app.api.system import router as system_router  # noqa: E402

router.include_router(search_router)
router.include_router(system_router)

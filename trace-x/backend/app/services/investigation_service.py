"""Investigation CRUD + dashboard statistics."""
from __future__ import annotations

import os

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.integrity.ledger import ledger
from app.models.models import (
    Event,
    Evidence,
    Finding,
    Investigation,
)
from app.schemas.schemas import InvestigationCreate, InvestigationUpdate
from app.services.audit_service import log_action


def create_investigation(db: Session, data: InvestigationCreate, actor: str = "investigator") -> Investigation:
    if data.severity not in ("Low", "Medium", "High", "Critical"):
        raise HTTPException(status_code=422, detail="Severity must be Low, Medium, High or Critical.")
    if data.status not in ("Open", "Investigating", "Contained", "Resolved", "Archived"):
        raise HTTPException(status_code=422, detail="Invalid investigation status.")
    if data.incident_type not in (
            "Phishing", "Malware", "Unauthorized Access", "Account Compromise", "Data Exfiltration",
            "Ransomware", "Insider Threat", "Network Intrusion", "Web Attack", "Other"):
        raise HTTPException(status_code=422, detail="Invalid incident type.")

    investigation = Investigation(
        name=data.name.strip(), description=data.description or "",
        investigator=data.investigator or "unassigned",
        incident_type=data.incident_type, severity=data.severity, status=data.status,
    )
    db.add(investigation)
    db.flush()
    ledger.add_record(db, action="investigation_created", investigation_id=investigation.id,
                      payload={"code": investigation.code, "name": investigation.name,
                               "severity": investigation.severity})
    log_action(db, action="investigation_created", investigation_id=investigation.id,
               object_id=investigation.code, actor=actor,
               details={"incident_type": investigation.incident_type})
    db.commit()
    db.refresh(investigation)
    return investigation


def update_investigation(db: Session, investigation: Investigation, data: InvestigationUpdate) -> Investigation:
    changes = {}
    for field, value in data.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(investigation, field, value)
            changes[field] = value
    log_action(db, action="investigation_updated", investigation_id=investigation.id,
               object_id=investigation.code, details=changes)
    db.commit()
    db.refresh(investigation)
    return investigation


def delete_investigation(db: Session, investigation: Investigation) -> None:
    db.delete(investigation)
    log_action(db, action="investigation_deleted", investigation_id=None,
               object_id=investigation.code, details={"name": investigation.name})
    db.commit()


def get_investigation(db: Session, investigation_id: int) -> Investigation:
    investigation = db.get(Investigation, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation


def investigation_stats(db: Session, investigation: Investigation) -> dict:
    evidence_count = db.scalar(select(func.count(Evidence.id)).where(
        Evidence.investigation_id == investigation.id)) or 0
    event_count = db.scalar(select(func.count(Event.id)).where(
        Event.investigation_id == investigation.id)) or 0
    suspicious = db.scalar(select(func.count(Event.id)).where(
        Event.investigation_id == investigation.id, Event.is_suspicious.is_(True))) or 0
    finding_count = db.scalar(select(func.count(Finding.id)).where(
        Finding.investigation_id == investigation.id)) or 0
    violations = db.scalar(select(func.count(Evidence.id)).where(
        Evidence.investigation_id == investigation.id,
        Evidence.integrity_status.in_(["Violation", "Missing"]))) or 0
    return {
        "evidence_count": evidence_count,
        "event_count": event_count,
        "suspicious_event_count": suspicious,
        "finding_count": finding_count,
        "integrity_status": "Verified" if violations == 0 else "Violation",
    }


def dashboard_stats(db: Session) -> dict:
    total = db.scalar(select(func.count(Investigation.id))) or 0
    active = db.scalar(select(func.count(Investigation.id)).where(
        Investigation.status.in_(["Open", "Investigating"]))) or 0
    evidence_count = db.scalar(select(func.count(Evidence.id))) or 0
    suspicious = db.scalar(select(func.count(Event.id)).where(Event.is_suspicious.is_(True))) or 0
    critical_findings = db.scalar(select(func.count(Finding.id)).where(
        Finding.severity.in_(["Critical", "High"]))) or 0
    violations = db.scalar(select(func.count(Evidence.id)).where(
        Evidence.integrity_status.in_(["Violation", "Missing"]))) or 0

    recent = db.scalars(select(Investigation).order_by(Investigation.updated_at.desc()).limit(6)).all()
    recent_evidence = db.scalars(select(Evidence).order_by(Evidence.id.desc()).limit(6)).all()
    inv_by_id = {i.id: i for i in db.scalars(select(Investigation))}

    findings_by_severity = dict(db.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)).all())
    events_by_type = dict(db.execute(
        select(Event.event_type, func.count(Event.id))
        .where(Event.is_suspicious.is_(True))
        .group_by(Event.event_type)).all())

    return {
        "total_investigations": total,
        "active_investigations": active,
        "evidence_items": evidence_count,
        "suspicious_events": suspicious,
        "critical_findings": critical_findings,
        "integrity_violations": violations,
        "recent_investigations": [
            dict(investigation_out(db, inv)) for inv in recent
        ],
        "recent_evidence": [
            {
                "id": ev.id, "code": ev.code, "original_filename": ev.original_filename,
                "investigation_code": inv_by_id[ev.investigation_id].code if ev.investigation_id in inv_by_id else None,
                "investigation_id": ev.investigation_id,
                "file_type": ev.file_type, "size": ev.size,
                "sha256": ev.sha256, "integrity_status": ev.integrity_status,
                "status": ev.status, "uploaded_at": ev.uploaded_at,
            } for ev in recent_evidence
        ],
        "findings_by_severity": findings_by_severity,
        "suspicious_by_type": events_by_type,
    }


def investigation_out(db: Session, investigation: Investigation) -> dict:
    stats = investigation_stats(db, investigation)
    return {
        "id": investigation.id, "code": investigation.code, "name": investigation.name,
        "description": investigation.description, "investigator": investigation.investigator,
        "incident_type": investigation.incident_type, "severity": investigation.severity,
        "status": investigation.status,
        "created_at": investigation.created_at, "updated_at": investigation.updated_at,
        **stats,
    }

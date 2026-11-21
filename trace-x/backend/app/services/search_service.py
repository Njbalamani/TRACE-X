"""Global search across investigations, evidence, events and findings."""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.models import Event, Evidence, Finding, Investigation


def global_search(db: Session, query: str, limit: int = 40) -> list[dict]:
    q = (query or "").strip()
    if not q:
        return []
    like = f"%{q}%"
    hits: list[dict] = []

    investigations = db.scalars(select(Investigation).where(or_(
        Investigation.name.ilike(like),
        Investigation.description.ilike(like),
        Investigation.investigator.ilike(like),
    ))).all()
    for inv in investigations[:limit]:
        hits.append({
            "kind": "investigation", "id": inv.id, "code": inv.code,
            "title": inv.name, "detail": f"{inv.incident_type} · {inv.severity} · {inv.status}",
            "investigation_code": inv.code, "investigation_id": inv.id,
        })

    evidences = db.scalars(select(Evidence).where(or_(
        Evidence.original_filename.ilike(like),
        Evidence.sha256.ilike(like),
        Evidence.description.ilike(like),
    ))).all()
    inv_by_id = {i.id: i for i in db.scalars(select(Investigation))}
    for ev in evidences[:limit]:
        inv = inv_by_id.get(ev.investigation_id)
        hits.append({
            "kind": "evidence", "id": ev.id, "code": ev.code,
            "title": ev.original_filename,
            "detail": f"SHA-256 {ev.sha256[:24]}… · {ev.status}",
            "investigation_code": inv.code if inv else None,
            "investigation_id": ev.investigation_id,
        })

    events = db.scalars(select(Event).where(or_(
        Event.username.ilike(like),
        Event.source_ip.ilike(like),
        Event.destination_ip.ilike(like),
        Event.hostname.ilike(like),
        Event.domain.ilike(like),
        Event.url.ilike(like),
        Event.file_path.ilike(like),
        Event.message.ilike(like),
        Event.event_type.ilike(like),
    )).order_by(Event.id.desc())).all()
    for e in events[:limit]:
        inv = inv_by_id.get(e.investigation_id)
        evidence = db.get(Evidence, e.evidence_id)
        hits.append({
            "kind": "event", "id": e.id, "code": e.code,
            "title": e.message or f"{e.event_type} @ {e.timestamp or '—'}",
            "detail": f"{e.event_type} · {e.timestamp or '—'} · evidence {evidence.code if evidence else '—'}",
            "investigation_code": inv.code if inv else None,
            "investigation_id": e.investigation_id,
        })

    findings = db.scalars(select(Finding).where(or_(
        Finding.title.ilike(like),
        Finding.conclusion.ilike(like),
        Finding.explanation.ilike(like),
    ))).all()
    for f in findings[:limit]:
        inv = inv_by_id.get(f.investigation_id)
        hits.append({
            "kind": "finding", "id": f.id, "code": f.code,
            "title": f.title,
            "detail": f"{f.severity} · {f.confidence} · {f.classification}",
            "investigation_code": inv.code if inv else None,
            "investigation_id": f.investigation_id,
        })

    return hits

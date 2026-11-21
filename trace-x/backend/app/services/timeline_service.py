"""Timeline construction from suspicious events + stage classification."""
from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.analyzers.stages import classify_event_stage
from app.models.models import Event, TimelineEvent


def rebuild_timeline(db: Session, investigation_id: int, suspicious_events: list[Event],
                     stage_list: list[dict]) -> int:
    db.execute(delete(TimelineEvent).where(TimelineEvent.investigation_id == investigation_id))

    ordered = sorted([e for e in suspicious_events], key=lambda e: (e.timestamp or "9999", e.id))

    count = 0
    for index, event in enumerate(ordered):
        st = classify_event_stage(event)
        narrative = event.message or f"{event.event_type.replace('_', ' ').title()}"
        if event.username:
            narrative += f" — user '{event.username}'"
        if event.source_ip:
            narrative += f" — source {event.source_ip}"
        if event.file_path:
            narrative += f" — {event.file_path}"
        db.add(TimelineEvent(
            investigation_id=investigation_id,
            event_id=event.id,
            order_index=index,
            attack_stage=st,
            narrative=narrative[:1000],
        ))
        count += 1
    db.flush()
    return count


def get_timeline(db: Session, investigation_id: int) -> list[dict]:
    rows = db.scalars(select(TimelineEvent).where(
        TimelineEvent.investigation_id == investigation_id).order_by(TimelineEvent.order_index)).all()
    out = []
    for row in rows:
        event = db.get(Event, row.event_id)
        if not event:
            continue
        out.append({
            "order_index": row.order_index,
            "event_id": event.id,
            "event_code": event.code,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "narrative": row.narrative,
            "attack_stage": row.attack_stage,
            "severity": event.severity,
            "is_suspicious": event.is_suspicious,
            "username": event.username,
            "source_ip": event.source_ip,
            "message": event.message,
            "evidence_code": event.evidence.code if event.evidence else None,
            "evidence_id": event.evidence_id,
        })
    return out

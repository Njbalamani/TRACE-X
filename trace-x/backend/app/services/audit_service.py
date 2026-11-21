"""Audit logging for investigator actions."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.models import AuditLog


def log_action(db: Session, *, action: str, actor: str = "investigator",
               investigation_id: int | None = None, object_id: str | None = None,
               details: dict | None = None) -> AuditLog:
    entry = AuditLog(
        actor=actor or "investigator",
        investigation_id=investigation_id,
        object_id=object_id,
        action=action,
        details=details or {},
    )
    db.add(entry)
    db.flush()
    return entry

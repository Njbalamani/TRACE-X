"""SQLAlchemy models. Display codes (CASE-2026-001, EV-0001, EVT-0001, FND-0001)
are derived from integer primary keys so they are guaranteed unique."""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _dt(v: datetime | None) -> str | None:
    return v.isoformat() if v else None


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Investigation(Base, TimestampMixin):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    investigator: Mapped[str] = mapped_column(String(120), default="")
    incident_type: Mapped[str] = mapped_column(String(60), default="Other")
    severity: Mapped[str] = mapped_column(String(20), default="Medium")
    status: Mapped[str] = mapped_column(String(20), default="Open")

    @property
    def code(self) -> str:
        return f"CASE-2026-{self.id:03d}"

    evidence: Mapped[list["Evidence"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    file_type: Mapped[str] = mapped_column(String(20), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(120), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="Processing")  # Processing/Processed/Failed/Metadata only
    integrity_status: Mapped[str] = mapped_column(String(30), default="Verified")  # Verified/Violation/Missing
    parser_name: Mapped[str] = mapped_column(String(40), default="")
    parse_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    investigation: Mapped[Investigation] = relationship(back_populates="evidence")
    events: Mapped[list["Event"]] = relationship(back_populates="evidence", cascade="all, delete-orphan")

    @property
    def code(self) -> str:
        return f"EV-{self.id:04d}"


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_inv_time", "investigation_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"), index=True)

    timestamp: Mapped[str | None] = mapped_column(String(40), index=True)
    event_type: Mapped[str] = mapped_column(String(60), default="GENERIC", index=True)
    username: Mapped[str | None] = mapped_column(String(120), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(120), index=True)
    action: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str | None] = mapped_column(String(40))
    port: Mapped[str | None] = mapped_column(String(16))
    file_path: Mapped[str | None] = mapped_column(Text)
    byte_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(80))
    process_id: Mapped[str | None] = mapped_column(String(40))
    domain: Mapped[str | None] = mapped_column(String(255), index=True)
    url: Mapped[str | None] = mapped_column(Text)
    file_hash: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(Text)
    raw_line: Mapped[str | None] = mapped_column(Text)

    is_suspicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    suspicion_reason: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(20))

    evidence: Mapped[Evidence] = relationship(back_populates="events")

    @property
    def code(self) -> str:
        return f"EVT-{self.id:04d}"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    analysis_run_id: Mapped[int | None] = mapped_column(ForeignKey("analysis_runs.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), default="Medium")  # Low/Medium/High/Critical
    confidence: Mapped[str] = mapped_column(String(20), default="Medium")  # High/Medium/Low
    classification: Mapped[str] = mapped_column(String(30), default="Possible")  # Confirmed/Likely/Possible/Insufficient Evidence
    attack_stage: Mapped[str | None] = mapped_column(String(60))
    conclusion: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")  # concise evidence-based explanation (no hidden CoT)
    supporting_evidence_ids: Mapped[list] = mapped_column(JSON, default=list)  # ["EV-0001", ...]
    supporting_event_ids: Mapped[list] = mapped_column(JSON, default=list)  # ["EVT-0002", ...]
    timestamps_involved: Mapped[list] = mapped_column(JSON, default=list)
    excerpts: Mapped[list] = mapped_column(JSON, default=list)  # [{event_code, evidence_code, text, timestamp}]
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    origin: Mapped[str] = mapped_column(String(30), default="detection_rule")  # detection_rule | ai
    rule_id: Mapped[str | None] = mapped_column(String(60))
    status: Mapped[str] = mapped_column(String(20), default="New")  # New/Reviewed
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def code(self) -> str:
        return f"FND-{self.id:04d}"


class FindingEvidenceLink(Base):
    """Explicit finding -> (event, evidence) traceability links."""
    __tablename__ = "finding_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"), nullable=True)
    note: Mapped[str] = mapped_column(String(255), default="")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    order_index: Mapped[int] = mapped_column(Integer, default=0)
    attack_stage: Mapped[str | None] = mapped_column(String(60))
    narrative: Mapped[str] = mapped_column(Text, default="")


class IntegrityRecord(Base):
    """Append-only blockchain-style tamper-evident ledger."""
    __tablename__ = "integrity_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)  # per-chain sequence
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("investigations.id"), index=True, nullable=True)
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    data_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256 of the recorded payload
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)

    @property
    def code(self) -> str:
        return f"BLK-{self.id:04d}"


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    engine: Mapped[str] = mapped_column(String(40), default="deterministic")  # deterministic | openai
    status: Mapped[str] = mapped_column(String(20), default="Running")  # Running/Completed/Failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # executive summary, answers, correlation, stages

    @property
    def code(self) -> str:
        return f"RUN-{self.id:04d}"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id"), index=True)
    title: Mapped[str] = mapped_column(String(255), default="Investigation Report")
    formats: Mapped[list] = mapped_column(JSON, default=list)  # ["md","html","pdf"]
    md_path: Mapped[str] = mapped_column(String(500), default="")
    html_path: Mapped[str] = mapped_column(String(500), default="")
    pdf_path: Mapped[str] = mapped_column(String(500), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    @property
    def code(self) -> str:
        return f"RPT-{self.id:04d}"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(120), default="investigator")
    investigation_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(60))
    action: Mapped[str] = mapped_column(String(60), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

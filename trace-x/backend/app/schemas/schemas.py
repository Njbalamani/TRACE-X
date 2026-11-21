"""Pydantic v2 schemas (API contracts). All AI output is validated through
ai.schemas before it ever reaches these response models."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

SEVERITIES = ["Low", "Medium", "High", "Critical"]
STATUSES = ["Open", "Investigating", "Contained", "Resolved", "Archived"]
INCIDENT_TYPES = [
    "Phishing", "Malware", "Unauthorized Access", "Account Compromise",
    "Data Exfiltration", "Ransomware", "Insider Threat", "Network Intrusion",
    "Web Attack", "Other",
]


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class InvestigationCreate(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    description: str = ""
    investigator: str = Field(default="", max_length=120)
    incident_type: str = Field(default="Other")
    severity: str = Field(default="Medium")
    status: str = Field(default="Open")


class InvestigationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = None
    investigator: str | None = Field(default=None, max_length=120)
    incident_type: str | None = None
    severity: str | None = None
    status: str | None = None


class InvestigationOut(ORMModel):
    id: int
    code: str
    name: str
    description: str
    investigator: str
    incident_type: str
    severity: str
    status: str
    created_at: datetime
    updated_at: datetime
    evidence_count: int = 0
    event_count: int = 0
    suspicious_event_count: int = 0
    finding_count: int = 0
    integrity_status: str = "Verified"


class EvidenceOut(ORMModel):
    id: int
    code: str
    investigation_id: int
    investigation_code: str = ""
    original_filename: str
    stored_filename: str
    file_type: str
    size: int
    sha256: str
    source: str
    description: str
    status: str
    integrity_status: str
    parser_name: str
    parse_summary: dict
    event_count: int
    uploaded_at: datetime
    last_verified_at: datetime | None = None


class EventOut(ORMModel):
    id: int
    code: str
    investigation_id: int
    evidence_id: int
    evidence_code: str = ""
    timestamp: str | None
    event_type: str
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    hostname: str | None
    action: str | None
    status: str | None
    port: str | None
    file_path: str | None
    byte_count: int | None
    session_id: str | None
    process_id: str | None
    domain: str | None
    url: str | None
    file_hash: str | None
    message: str | None
    raw_line: str | None
    is_suspicious: bool
    suspicion_reason: str | None
    severity: str | None


class FindingOut(ORMModel):
    id: int
    code: str
    investigation_id: int
    investigation_code: str = ""
    title: str
    severity: str
    confidence: str
    classification: str
    attack_stage: str | None
    conclusion: str
    explanation: str
    supporting_evidence_ids: list
    supporting_event_ids: list
    timestamps_involved: list
    excerpts: list
    recommendations: list
    origin: str
    rule_id: str | None
    status: str
    generated_at: datetime


class AnalysisRunOut(ORMModel):
    id: int
    code: str
    investigation_id: int
    engine: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    error: str | None
    summary: dict


class TimelineItemOut(BaseModel):
    order_index: int
    event_id: int
    event_code: str
    timestamp: str | None
    event_type: str
    narrative: str
    attack_stage: str | None
    severity: str | None
    is_suspicious: bool
    username: str | None
    source_ip: str | None
    message: str | None
    evidence_code: str
    evidence_id: int


class LedgerOut(ORMModel):
    id: int
    code: str
    sequence: int
    investigation_id: int | None
    evidence_id: int | None
    action: str
    data_hash: str
    previous_hash: str
    current_hash: str
    timestamp: datetime
    payload: dict


class IntegrityStatusOut(BaseModel):
    investigation_code: str
    chain_valid: bool
    chain_error: str | None = None
    total_evidence: int
    verified: int
    modified: int
    missing: int
    integrity_violations: int
    ledger_length: int
    items: list["EvidenceIntegrityItem"]


class EvidenceIntegrityItem(BaseModel):
    evidence_code: str
    filename: str
    stored_hash: str
    current_hash: str | None
    status: str  # VERIFIED / INTEGRITY VIOLATION / MISSING
    last_verified_at: datetime | None = None


class ReportOut(ORMModel):
    id: int
    code: str
    investigation_id: int
    investigation_code: str = ""
    title: str
    formats: list
    sha256: str
    created_at: datetime


class SearchHit(BaseModel):
    kind: str  # investigation | evidence | event | finding
    id: int
    code: str
    title: str
    detail: str
    investigation_code: str | None = None
    investigation_id: int | None = None


class SystemInfoOut(BaseModel):
    app: str
    version: str
    ai_provider: str
    ai_provider_mode: str  # "external" | "local-deterministic"
    database_url: str
    evidence_storage: str
    report_storage: str
    max_upload_mb: int


class PaginatedFindings(BaseModel):
    total: int
    items: list[FindingOut]


class PaginatedEvents(BaseModel):
    total: int
    items: list[EventOut]


IntegrityStatusOut.model_rebuild()

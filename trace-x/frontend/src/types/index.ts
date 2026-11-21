// API contract types (mirrors backend/app/schemas)

export type Severity = "Low" | "Medium" | "High" | "Critical";
export type Confidence = "Low" | "Medium" | "High";
export type Classification = "Confirmed" | "Likely" | "Possible" | "Insufficient Evidence";
export type CaseStatus = "Open" | "Investigating" | "Contained" | "Resolved" | "Archived";

export interface Investigation {
  id: number;
  code: string;
  name: string;
  description: string;
  investigator: string;
  incident_type: string;
  severity: Severity;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
  evidence_count: number;
  event_count: number;
  suspicious_event_count: number;
  finding_count: number;
  integrity_status: string;
}

export interface Evidence {
  id: number;
  code: string;
  investigation_id: number;
  investigation_code?: string;
  original_filename: string;
  stored_filename: string;
  file_type: string;
  size: number;
  sha256: string;
  source: string;
  description: string;
  status: string;
  integrity_status: string;
  parser_name: string;
  parse_summary: Record<string, unknown>;
  event_count: number;
  uploaded_at: string;
  last_verified_at: string | null;
  events?: NormalizedEvent[];
}

export interface NormalizedEvent {
  id: number;
  code: string;
  investigation_id: number;
  evidence_id: number;
  evidence_code?: string;
  timestamp: string | null;
  event_type: string;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  hostname: string | null;
  action: string | null;
  status: string | null;
  port: string | null;
  file_path: string | null;
  byte_count: number | null;
  session_id: string | null;
  process_id: string | null;
  domain: string | null;
  url: string | null;
  file_hash: string | null;
  message: string | null;
  raw_line: string | null;
  is_suspicious: boolean;
  suspicion_reason: string | null;
  severity: Severity | null;
  related_events?: { code: string; timestamp: string | null; event_type: string; message: string; evidence_code: string | null }[];
}

export interface Excerpt {
  event_code: string;
  evidence_code: string | null;
  timestamp: string | null;
  text: string;
}

export interface Finding {
  id: number;
  code: string;
  investigation_id: number;
  investigation_code?: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  classification: Classification;
  attack_stage: string | null;
  conclusion: string;
  explanation: string;
  supporting_evidence_ids: string[];
  supporting_event_ids: string[];
  timestamps_involved: string[];
  excerpts: Excerpt[];
  recommendations: string[];
  origin: string;
  rule_id: string | null;
  status: string;
  generated_at: string;
}

export interface CorrelationChain {
  chain_id: string;
  event_count: number;
  suspicious_count: number;
  event_ids: string[];
  context_event_ids: string[];
  evidence_ids: string[];
  shared_attributes: Record<string, string[]>;
  time_span: { start: string | null; end: string | null };
  sequence: { event_code: string; timestamp: string | null; event_type: string; username: string | null; source_ip: string | null; summary: string }[];
}

export interface AttackStage {
  stage: string;
  confidence: Confidence;
  event_count: number;
  event_ids: string[];
  evidence_ids: string[];
  timestamps: string[];
  summary: string;
}

export interface AnalysisSummary {
  engine: string;
  executive_summary: string;
  what_happened: string;
  suspicious_activities: string[];
  affected_systems: string[];
  affected_users: string[];
  confirmed: string[];
  suspected: string[];
  missing_information: string[];
  next_steps: string[];
  correlation: { chains: CorrelationChain[]; correlated_events: number; link_counts: Record<string, number>; note: string };
  attack_stages: AttackStage[];
  counts: { events: number; suspicious_events: number; findings: number; chains: number; stages: number };
  timeline_span: { start: string | null; end: string | null };
}

export interface AnalysisRun {
  id: number;
  code: string;
  investigation_id: number;
  engine: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  summary: AnalysisSummary;
}

export interface TimelineItem {
  order_index: number;
  event_id: number;
  event_code: string;
  timestamp: string | null;
  event_type: string;
  narrative: string;
  attack_stage: string | null;
  severity: Severity | null;
  is_suspicious: boolean;
  username: string | null;
  source_ip: string | null;
  message: string | null;
  evidence_code: string;
  evidence_id: number;
}

export interface LedgerRecord {
  id: number;
  code: string;
  sequence: number;
  investigation_id: number | null;
  evidence_id: number | null;
  action: string;
  data_hash: string;
  previous_hash: string;
  current_hash: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

export interface IntegrityResult {
  investigation_code: string;
  chain_valid: boolean;
  chain_error: string | null;
  total_evidence: number;
  verified: number;
  modified: number;
  missing: number;
  integrity_violations: number;
  ledger_length: number;
  items: {
    evidence_code: string;
    filename: string;
    stored_hash: string;
    current_hash: string | null;
    status: string;
    last_verified_at: string | null;
  }[];
}

export interface Report {
  id: number;
  code: string;
  investigation_id: number;
  investigation_code?: string;
  title: string;
  formats: string[];
  sha256: string;
  created_at: string;
}

export interface DashboardStats {
  total_investigations: number;
  active_investigations: number;
  evidence_items: number;
  suspicious_events: number;
  critical_findings: number;
  integrity_violations: number;
  recent_investigations: Investigation[];
  recent_evidence: (Evidence & { investigation_code: string | null })[];
  findings_by_severity: Record<string, number>;
  suspicious_by_type: Record<string, number>;
}

export interface SearchHit {
  kind: "investigation" | "evidence" | "event" | "finding";
  id: number;
  code: string;
  title: string;
  detail: string;
  investigation_code: string | null;
  investigation_id: number | null;
}

export interface SystemInfo {
  app: string;
  version: string;
  ai_provider: string;
  ai_provider_mode: string;
  database_url: string;
  evidence_storage: string;
  report_storage: string;
  max_upload_mb: number;
  privacy_note?: string;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  object_id: string | null;
  details: Record<string, unknown>;
}

export interface EvidencePreview {
  evidence_code: string;
  original_filename: string;
  sha256: string;
  size: number;
  integrity_status: string;
  parse_summary: Record<string, unknown>;
  preview: string | null;
  preview_truncated: boolean;
  content_type: string;
}

export const INCIDENT_TYPES = [
  "Phishing", "Malware", "Unauthorized Access", "Account Compromise", "Data Exfiltration",
  "Ransomware", "Insider Threat", "Network Intrusion", "Web Attack", "Other",
];
export const SEVERITIES: Severity[] = ["Low", "Medium", "High", "Critical"];
export const CASE_STATUSES: CaseStatus[] = ["Open", "Investigating", "Contained", "Resolved", "Archived"];

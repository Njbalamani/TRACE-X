"""Canonical normalized-event helpers shared by every parser.

Every normalized event MUST reference its source evidence — parsers receive
evidence_id/evidence_code and stamp it onto each event dict."""
from __future__ import annotations

import re
from datetime import datetime

# Canonical event types
LOGIN_FAILURE = "LOGIN_FAILURE"
LOGIN_SUCCESS = "LOGIN_SUCCESS"
PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
FILE_ACCESS = "FILE_ACCESS"
DATA_TRANSFER = "DATA_TRANSFER"
NETWORK_CONNECTION = "NETWORK_CONNECTION"
EMAIL_RECEIVED = "EMAIL_RECEIVED"
ALERT = "SECURITY_ALERT"
MALWARE = "MALWARE_EVENT"
ACCOUNT_CHANGE = "ACCOUNT_CHANGE"
GENERIC = "GENERIC"

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

# Field aliases -> canonical field (lowercased key match)
FIELD_ALIASES = {
    "user": "username", "username": "username", "account": "username", "login": "username",
    "source_ip": "source_ip", "src_ip": "source_ip", "src": "source_ip", "source": "source_ip",
    "source address": "source_ip", "client_ip": "source_ip", "remote_ip": "source_ip", "ip": "source_ip",
    "destination_ip": "destination_ip", "dest_ip": "destination_ip", "dst_ip": "destination_ip",
    "dst": "destination_ip", "dest": "destination_ip", "destination": "destination_ip",
    "target_ip": "destination_ip", "destination address": "destination_ip",
    "event": "event_type", "event_type": "event_type", "type": "event_type", "category": "event_type",
    "action": "action", "operation": "action",
    "status": "status", "result": "status", "outcome": "status", "state": "status",
    "host": "hostname", "hostname": "hostname", "computer": "hostname", "server": "hostname", "node": "hostname",
    "port": "port", "destination_port": "port", "dst_port": "port", "dest_port": "port",
    "file": "file_path", "file_path": "file_path", "filename": "file_path", "path": "file_path", "filepath": "file_path",
    "bytes": "byte_count", "size": "byte_count", "bytes_transfered": "byte_count",
    "bytes_transferred": "byte_count", "data_size": "byte_count", "sent_bytes": "byte_count",
    "session": "session_id", "session_id": "session_id",
    "pid": "process_id", "process_id": "process_id", "process": "process_id",
    "domain": "domain", "url": "url", "uri": "url",
    "hash": "file_hash", "file_hash": "file_hash", "sha256": "file_hash", "md5": "file_hash",
    "message": "message", "msg": "message", "description": "message", "details": "message",
}

STATUS_FAILURE_WORDS = {"failed", "failure", "fail", "denied", "invalid", "error", "rejected", "bad"}
STATUS_SUCCESS_WORDS = {"success", "successful", "accepted", "ok", "granted", "allowed", "passed"}


def normalize_timestamp(raw) -> str | None:
    """Return an ISO 'YYYY-MM-DD HH:MM:SS' string for many common formats."""
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw.strftime("%Y-%m-%d %H:%M:%S")
    raw = str(raw).strip()
    if not raw:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    # ISO with timezone e.g. 2026-10-07T10:04:41+00:00 / Z
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", raw)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    # syslog style 'Oct  7 10:04:41' -> assume current year
    try:
        dt = datetime.strptime(f"{datetime.now().year} {raw}", "%Y %b %d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def classify_event(action: str | None, status: str | None, message: str | None,
                   declared_type: str | None = None) -> str:
    """Infer a canonical event type from available text."""
    text = " ".join(filter(None, [declared_type, action, status, message])).lower()
    if declared_type:
        dt = declared_type.strip().upper()
        known = {LOGIN_FAILURE, LOGIN_SUCCESS, PRIVILEGE_ESCALATION, FILE_ACCESS,
                 DATA_TRANSFER, NETWORK_CONNECTION, EMAIL_RECEIVED, ALERT, MALWARE, ACCOUNT_CHANGE}
        if dt in known:
            return dt
    if "failed password" in text or ("login" in text and any(w in text for w in STATUS_FAILURE_WORDS)) \
            or "auth failure" in text or "failed authentication" in text:
        return LOGIN_FAILURE
    if ("accepted password" in text or "login success" in text or "session opened" in text
            or ("login" in text and any(w in text for w in STATUS_SUCCESS_WORDS))):
        return LOGIN_SUCCESS
    if "sudo" in text or "privilege" in text or "runas" in text or "root command" in text:
        return PRIVILEGE_ESCALATION
    if any(k in text for k in ("malware", "virus", "trojan", "ransom", "worm")):
        return MALWARE
    if any(k in text for k in ("exfiltration", "outbound transfer", "data transfer", "upload",
                               "bytes=", "transfer outbound", "large transfer")):
        return DATA_TRANSFER
    if any(k in text for k in ("file access", "accessed file", "file read", "file_access",
                               "opened file", "downloaded file", "copied file")):
        return FILE_ACCESS
    if any(k in text for k in ("allow ", "deny ", "connection from", "connected to", "firewall", "tcp ", "udp ")):
        return NETWORK_CONNECTION
    if "email" in text or "phishing" in text or "smtp" in text:
        return EMAIL_RECEIVED
    if "alert" in text:
        return ALERT
    return GENERIC or "GENERIC"


def normalize_status(status: str | None, message: str | None = None) -> str | None:
    text = " ".join(filter(None, [status, message])).lower()
    if not text:
        return None
    if any(w in text for w in STATUS_FAILURE_WORDS):
        return "failed"
    if any(w in text for w in STATUS_SUCCESS_WORDS):
        return "success"
    return (status or None)


def normalize_event(evidence_id: int, evidence_code: str, **kwargs) -> dict:
    """Build one canonical normalized event dict with mandatory evidence reference."""
    declared = kwargs.get("declared_type")
    action = (kwargs.get("action") or "").strip() or None
    status = normalize_status(kwargs.get("status"), kwargs.get("message"))
    message = kwargs.get("message")
    event_type = classify_event(action, status, message, declared)
    if event_type == GENERIC:
        event_type = "GENERIC"
    ev = {
        "timestamp": normalize_timestamp(kwargs.get("timestamp")),
        "event_type": event_type,
        "username": kwargs.get("username"),
        "source_ip": kwargs.get("source_ip"),
        "destination_ip": kwargs.get("destination_ip"),
        "hostname": kwargs.get("hostname"),
        "action": action,
        "status": status,
        "port": str(kwargs.get("port")) if kwargs.get("port") not in (None, "") else None,
        "file_path": kwargs.get("file_path"),
        "byte_count": kwargs.get("byte_count"),
        "session_id": kwargs.get("session_id"),
        "process_id": kwargs.get("process_id"),
        "domain": kwargs.get("domain"),
        "url": kwargs.get("url"),
        "file_hash": kwargs.get("file_hash"),
        "message": (str(message)[:1000] if message else None),
        "raw_line": (str(kwargs.get("raw_line"))[:2000] if kwargs.get("raw_line") else None),
        "source_evidence_id": evidence_code,   # MANDATORY traceability reference
        "_evidence_id": evidence_id,
    }
    return {k: v for k, v in ev.items() if v is not None}


def extract_ips(text: str) -> list[str]:
    return IP_RE.findall(text or "")


def extract_first_url(text: str) -> str | None:
    m = URL_RE.search(text or "")
    return m.group(0) if m else None


def extract_domain(url_or_text: str) -> str | None:
    m = URL_RE.search(url_or_text or "")
    target = m.group(0) if m else (url_or_text or "")
    dm = DOMAIN_RE.search(target.replace("https://", "").replace("http://", ""))
    return dm.group(0).lower() if dm else None
